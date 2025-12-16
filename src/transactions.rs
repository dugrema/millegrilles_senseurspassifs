use std::collections::HashMap;
use log::{debug, error, warn};

use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::{chrono, serde_json};
use millegrilles_common_rust::base64::engine::DecodePaddingMode::RequireNone;
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, convertir_to_bson, filtrer_doc_id, MongoDao};
use millegrilles_common_rust::transactions::Transaction;
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::db_structs::TransactionValide;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::mongodb::options::{FindOneAndUpdateOptions, FindOneOptions, Hint, InsertOneOptions, ReturnDocument, UpdateOptions, WriteConcern};
use millegrilles_common_rust::serde_json::json;
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::error::Error;
use millegrilles_common_rust::middleware::{sauvegarder_traiter_transaction_serializable, sauvegarder_traiter_transaction_serializable_v2};
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::{epochseconds, optionepochseconds};
use millegrilles_common_rust::bson::serde_helpers::chrono_datetime_as_bson_datetime;
use millegrilles_common_rust::mongodb::ClientSession;
use crate::common::*;
use crate::domain_manager::SenseursPassifsDomainManager;

pub async fn aiguillage_transaction<M>(
    gestionnaire: &SenseursPassifsDomainManager, middleware: &M, transaction: TransactionValide, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    let action = match transaction.transaction.routage.as_ref() {
        Some(inner) => match inner.action.as_ref() {
            Some(inner) => inner.clone(),
            None => Err(Error::String(format!("senseurspassifs.aiguillage_transaction: Transaction {} n'a pas d'action - SKIP", transaction.transaction.id)))?
        },
        None => Err(Error::String(format!("senseurspassifs.aiguillage_transaction: Transaction {} n'a pas d'action - SKIP", transaction.transaction.id)))?
    };

    debug!("aiguillage_transaction {}", action);

    match action.as_str() {
        TRANSACTION_MAJ_SENSEUR => transaction_maj_senseur(middleware, transaction, gestionnaire, session).await,
        TRANSACTION_MAJ_NOEUD => transaction_maj_noeud(middleware, transaction,  session).await,
        TRANSACTION_SUPPRESSION_SENSEUR => transaction_suppression_senseur(middleware, transaction, session).await,
        TRANSACTION_MAJ_APPAREIL => transaction_maj_appareil(middleware, transaction, gestionnaire, session).await,
        TRANSACTION_SENSEUR_HORAIRE => transaction_senseur_horaire(middleware, transaction, session).await,
        TRANSACTION_INIT_APPAREIL => transaction_initialiser_appareil(middleware, transaction, session).await,
        TRANSACTION_APPAREIL_SUPPRIMER => transaction_appareil_supprimer(middleware, transaction, session).await,
        TRANSACTION_APPAREIL_RESTAURER => transaction_appareil_restaurer(middleware, transaction, session).await,
        TRANSACTION_MAJ_CONFIGURATION_USAGER => transaction_maj_configuration_usager(middleware, transaction, session).await,
        TRANSACTION_SAUVEGARDER_PROGRAMME => transaction_sauvegarder_programme(middleware, transaction, gestionnaire, session).await,

        // Legacy
        TRANSACTION_LECTURE => transaction_lectures(middleware, transaction, session).await,

        _ => Err(Error::String(format!("senseurspassifs.aiguillage_transaction: Transaction {} est de type non gere : {}", transaction.transaction.id, action))),
    }
}

async fn transaction_maj_senseur<M>(
    middleware: &M, transaction: TransactionValide, gestionnaire: &SenseursPassifsDomainManager, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("transaction_maj_senseur Consommer transaction : {:?}", &transaction.transaction.id);
    let transaction_cle: TransactionMajSenseur = serde_json::from_str(transaction.transaction.contenu.as_str())?;

    let user_id = match transaction.certificat.get_user_id()? {
        Some(user) => user,
        None => Err(Error::Str("senseurspassifs.transaction_maj_senseur Erreur user_id absent du certificat"))?
    };

    let collection = middleware.get_collection(COLLECTIONS_LECTURES)?;

    let document_transaction = {
        let mut set_ops = doc! {CHAMP_INSTANCE_ID: &transaction_cle.instance_id};

        let mut valeur_transactions = match convertir_to_bson(transaction_cle.clone()) {
            Ok(v) => v,
            Err(e) => Err(format!("senseurspassifs.transaction_maj_senseur Erreur conversion transaction en bson : {:?}", e))?
        };
        filtrer_doc_id(&mut valeur_transactions);
        valeur_transactions.remove("uuid_senseur");
        set_ops.extend(valeur_transactions);

        let ops = doc! {
            "$set": set_ops,
            "$setOnInsert": {
                CHAMP_CREATION: Utc::now(),
                CHAMP_UUID_SENSEUR: &transaction_cle.uuid_senseur,
                CHAMP_USER_ID: &user_id,
            },
            "$currentDate": {CHAMP_MODIFICATION: true}
        };
        let filtre = doc! { CHAMP_UUID_SENSEUR: &transaction_cle.uuid_senseur, CHAMP_USER_ID: &user_id };
        let opts = FindOneAndUpdateOptions::builder().upsert(true).return_document(ReturnDocument::After).build();
        match collection.find_one_and_update_with_session(filtre, ops, Some(opts), session).await {
            Ok(r) => match r {
                Some(r) => match convertir_bson_deserializable::<TransactionMajSenseur>(r) {
                    Ok(r) => r,
                    Err(e) => Err(format!("senseurspassifs.transaction_maj_senseur Erreur conversion document senseur en doc TransactionMajSenseur: {:?}", e))?
                },
                None => Err(format!("senseurspassifs.transaction_maj_senseur Erreur chargement doc senseur apres MAJ"))?
            },
            Err(e) => Err(format!("senseurspassifs.transaction_maj_senseur Erreur traitement transaction senseur : {:?}", e))?
        }
    };
    debug!("transaction_maj_senseur Resultat maj transaction : {:?}", document_transaction);

    // Maj noeud
    {
        let filtre = doc! { CHAMP_INSTANCE_ID: &transaction_cle.instance_id };
        let ops = doc! {
            "$setOnInsert": {
                CHAMP_CREATION: Utc::now(),
                CHAMP_INSTANCE_ID: &transaction_cle.instance_id,
            },
            "$currentDate": {CHAMP_MODIFICATION: true}
        };
        let opts = UpdateOptions::builder().upsert(true).build();
        let collection_noeud = match middleware.get_collection(COLLECTIONS_INSTANCES) {
            Ok(n) => n,
            Err(e) => Err(format!("senseurspassifs.transaction_maj_senseur Erreur ouverture collection noeuds: {:?}", e))?
        };
        let resultat = match collection_noeud.update_one_with_session(filtre, ops, Some(opts), session).await {
            Ok(r) => r,
            Err(e) => Err(format!("senseurspassifs.transaction_maj_senseur Erreur traitement maj noeud : {:?}", e))?
        };

        if let Some(_) = resultat.upserted_id {
            debug!("transaction_maj_senseur Creer transaction pour instance_id {}", transaction_cle.instance_id);
            let transaction = TransactionMajNoeud::new(&transaction_cle.instance_id);
            // let routage = RoutageMessageAction::builder(DOMAINE_NOM, TRANSACTION_MAJ_NOEUD)
            //     .exchanges(vec![Securite::L4Secure])
            //     // .partition(&gestionnaire.instance_id)
            //     .blocking(false)
            //     .build();
            if let Err(e) = sauvegarder_traiter_transaction_serializable_v2(
                middleware, &transaction, gestionnaire, session, DOMAINE_NOM, TRANSACTION_MAJ_NOEUD).await
            {
                error!("senseurspassifs.transaction_maj_senseur Erreur sauvegarder_traiter_transaction_serializable pour instance_id {} : {:?}", transaction_cle.instance_id, e);
            }
        }
    }

    {
        let routage_evenement = RoutageMessageAction::builder(DOMAINE_NOM, TRANSACTION_MAJ_SENSEUR, vec![Securite::L2Prive])
            .partition(&user_id)
            .build();
        middleware.emettre_evenement(routage_evenement, &document_transaction).await?;
    }

    debug!("transaction_maj_senseur Resultat ajout transaction : {:?}", document_transaction);
    Ok(Some(middleware.build_reponse(&document_transaction)?.0))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionMajAppareil {
    pub uuid_appareil: String,
    pub configuration: ConfigurationAppareil,
}

async fn transaction_maj_appareil<M>(middleware: &M, transaction: TransactionValide, gestionnaire: &SenseursPassifsDomainManager, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao
{
    debug!("transaction_maj_senseur Consommer transaction : {:?}", transaction.transaction.id);
    let user_id = match transaction.certificat.get_user_id()? {
        Some(user) => user.to_owned(),
        None => Err(Error::Str("senseurspassifs.transaction_maj_senseur Erreur user_id absent du certificat"))?
    };

    let transaction_convertie: TransactionMajAppareil = serde_json::from_str(transaction.transaction.contenu.as_str())?;
    debug!("transaction_maj_senseur Transaction convertie: {:?}", transaction_convertie);

    let document_transaction: DocAppareil = {
        let mut set_ops = doc! {};
        let mut unset_ops = doc! {};

        if let Some(inner) = transaction_convertie.configuration.descriptif {
            set_ops.insert("configuration.descriptif", inner);
        }
        if let Some(inner) = transaction_convertie.configuration.cacher_senseurs {
            set_ops.insert("configuration.cacher_senseurs", inner);
        }
        if let Some(inner) = transaction_convertie.configuration.descriptif_senseurs {
            for (key, value) in inner {
                set_ops.insert(format!("configuration.descriptif_senseurs.{key}"), value);
            }
        }
        if let Some(inner) = transaction_convertie.configuration.displays {
            let bson_map = match convertir_to_bson(inner) {
                Ok(inner) => inner,
                Err(e) => Err(format!("senseurspassifs.transaction_maj_appareil Erreur conversion displays en bson : {:?}", e))?
            };
            set_ops.insert("configuration.displays", bson_map);
        }
        if let Some(inner) = transaction_convertie.configuration.programmes {
            let bson_map = match convertir_to_bson(inner) {
                Ok(inner) => inner,
                Err(e) => Err(format!("senseurspassifs.transaction_maj_appareil Erreur conversion programmes en bson : {:?}", e))?
            };
            set_ops.insert("configuration.programmes", bson_map);
        }
        if let Some(inner) = transaction_convertie.configuration.timezone {
            set_ops.insert("configuration.timezone".to_string(), inner);
        } else {
            unset_ops.insert("configuration.timezone".to_string(), true);
        }
        if let Some(inner) = transaction_convertie.configuration.geoposition {
            let bson_map = match convertir_to_bson(inner) {
                Ok(inner) => inner,
                Err(e) => Err(format!("senseurspassifs.transaction_maj_appareil Erreur conversion geoposition en bson : {:?}", e))?
            };
            set_ops.insert("configuration.geoposition", bson_map);
        } else {
            unset_ops.insert("configuration.geoposition", true);
        }
        if let Some(inner) = transaction_convertie.configuration.filtres_senseurs {
            for (key, value) in inner {
                set_ops.insert(format!("configuration.filtres_senseurs.{key}"), value);
            }
        }

        let mut ops = doc! {
            "$set": set_ops,
            "$setOnInsert": {
                CHAMP_CREATION: Utc::now(),
                CHAMP_UUID_APPAREIL: &transaction_convertie.uuid_appareil,
                CHAMP_USER_ID: &user_id,
            },
            "$currentDate": {CHAMP_MODIFICATION: true}
        };
        if unset_ops.len() > 0 {
            ops.insert("$unset", unset_ops);
        }

        let filtre = doc! { CHAMP_UUID_APPAREIL: &transaction_convertie.uuid_appareil, CHAMP_USER_ID: &user_id };
        let opts = FindOneAndUpdateOptions::builder()
            .upsert(true)
            .return_document(ReturnDocument::After)
            .build();

        let collection = middleware.get_collection(COLLECTIONS_APPAREILS)?;
        match collection.find_one_and_update_with_session(filtre, ops, Some(opts), session).await {
            Ok(r) => match r {
                Some(r) => match convertir_bson_deserializable(r) {
                    Ok(r) => r,
                    Err(e) => Err(format!("senseurspassifs.transaction_maj_appareil Erreur conversion document senseur en doc TransactionMajSenseur: {:?}", e))?
                },
                None => Err(format!("senseurspassifs.transaction_maj_appareil Erreur chargement doc senseur apres MAJ"))?
            },
            Err(e) => Err(format!("senseurspassifs.transaction_maj_appareil Erreur traitement transaction senseur : {:?}", e))?
        }
    };
    debug!("transaction_maj_appareil Resultat maj transaction : {:?}", document_transaction);

    // Evenement de mise a jour de l'appareil (web)
    {
        let routage_evenement = RoutageMessageAction::builder(DOMAINE_NOM, TRANSACTION_MAJ_APPAREIL, vec![Securite::L2Prive])
            .partition(&user_id)
            .build();
        middleware.emettre_evenement(routage_evenement, &document_transaction).await?;
    }

    if let Some(configuration) = &document_transaction.configuration {

        // Evenement de mise a jour des displays (relais)
        {
            let routage_evenement = RoutageMessageAction::builder(DOMAINE_NOM, EVENEMENT_MAJ_CONFIGURATION_APPAREIL, vec![Securite::L2Prive])
                .partition(&user_id)
                .build();
            let evenement = json!({
                CHAMP_USER_ID: &user_id,
                CHAMP_UUID_APPAREIL: &transaction_convertie.uuid_appareil,
                CHAMP_TIMEZONE: configuration.timezone.as_ref(),
            });
            middleware.emettre_evenement(routage_evenement, &evenement).await?;
        }

        // Evenement de mise a jour des displays (relais)
        if let Some(displays) = &configuration.displays {
            let routage_evenement = RoutageMessageAction::builder(DOMAINE_NOM, EVENEMENT_MAJ_DISPLAYS, vec![Securite::L2Prive])
                .partition(&user_id)
                .build();
            let evenement_displays = json!({
                CHAMP_UUID_APPAREIL: &transaction_convertie.uuid_appareil,
                "displays": displays
            });
            middleware.emettre_evenement(routage_evenement, &evenement_displays).await?;
        }

        // Evenement de mise a jour des programmes (relais)
        if let Some(programmes) = &configuration.programmes {
            let routage_evenement = RoutageMessageAction::builder(DOMAINE_NOM, EVENEMENT_MAJ_PROGRAMMES, vec![Securite::L2Prive])
                .partition(&user_id)
                .build();
            let evenement_programmes = json!({
                CHAMP_UUID_APPAREIL: &transaction_convertie.uuid_appareil,
                "programmes": programmes
            });
            middleware.emettre_evenement(routage_evenement, &evenement_programmes).await?;
        }
    }

    debug!("transaction_maj_appareil Resultat ajout transaction : {:?}", document_transaction);
    Ok(Some(middleware.build_reponse(&document_transaction)?.0))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionSauvegarderProgramme {
    pub uuid_appareil: String,
    pub programme: ProgrammeAppareil,
    pub supprimer: Option<bool>,
}

async fn transaction_sauvegarder_programme<M>(middleware: &M, transaction: TransactionValide, gestionnaire: &SenseursPassifsDomainManager, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao
{
    debug!("transaction_sauvegarder_programme Consommer transaction : {:?}", transaction.transaction.id);
    let user_id = match transaction.certificat.get_user_id()? {
        Some(user) => user.to_owned(),
        None => Err(Error::Str("senseurspassifs.transaction_sauvegarder_programme Erreur user_id absent du certificat"))?
    };

    let transaction_convertie: TransactionSauvegarderProgramme = serde_json::from_str(transaction.transaction.contenu.as_str())?;
    debug!("transaction_sauvegarder_programmes Transaction lue {:?}", transaction_convertie);

    let document_transaction: DocAppareil = {
        let mut set_ops = doc! {};
        let mut unset_ops = doc! {};

        let programme_id = transaction_convertie.programme.programme_id.clone();
        if let Some(true) = transaction_convertie.supprimer {
            unset_ops.insert(format!("configuration.programmes.{}", programme_id), true);
        } else {
            let bson_map = match convertir_to_bson(transaction_convertie.programme) {
                Ok(inner) => inner,
                Err(e) => Err(format!("senseurspassifs.transaction_sauvegarder_programme Erreur conversion programmes en bson : {:?}", e))?
            };
            set_ops.insert(format!("configuration.programmes.{}", programme_id), bson_map);
        }

        let mut ops = doc! {
            "$setOnInsert": {
                CHAMP_CREATION: Utc::now(),
                CHAMP_UUID_APPAREIL: &transaction_convertie.uuid_appareil,
                CHAMP_USER_ID: &user_id,
            },
            "$currentDate": {CHAMP_MODIFICATION: true}
        };
        if set_ops.len() > 0 {
            ops.insert("$set", set_ops);
        }
        if unset_ops.len() > 0 {
            ops.insert("$unset", unset_ops);
        }

        let filtre = doc! { CHAMP_UUID_APPAREIL: &transaction_convertie.uuid_appareil, CHAMP_USER_ID: &user_id };
        let opts = FindOneAndUpdateOptions::builder()
            .upsert(true)
            .return_document(ReturnDocument::After)
            .build();

        let collection = middleware.get_collection(COLLECTIONS_APPAREILS)?;
        match collection.find_one_and_update_with_session(filtre, ops, Some(opts), session).await {
            Ok(r) => match r {
                Some(r) => match convertir_bson_deserializable(r) {
                    Ok(r) => r,
                    Err(e) => Err(format!("senseurspassifs.transaction_sauvegarder_programme Erreur conversion document senseur en doc TransactionMajSenseur: {:?}", e))?
                },
                None => Err(format!("senseurspassifs.transaction_sauvegarder_programme Erreur chargement doc senseur apres MAJ"))?
            },
            Err(e) => Err(format!("senseurspassifs.transaction_sauvegarder_programme Erreur traitement transaction senseur : {:?}", e))?
        }
    };
    debug!("transaction_sauvegarder_programme Resultat maj transaction : {:?}", document_transaction);

    // Evenement de mise a jour de l'appareil (web)
    {
        let routage_evenement = RoutageMessageAction::builder(DOMAINE_NOM, TRANSACTION_MAJ_APPAREIL, vec![Securite::L2Prive])
            .partition(&user_id)
            .build();
        middleware.emettre_evenement(routage_evenement, &document_transaction).await?;
    }

    if let Some(configuration) = &document_transaction.configuration {

        // Evenement de mise a jour des programmes (relais)
        if let Some(programmes) = &configuration.programmes {
            let routage_evenement = RoutageMessageAction::builder(DOMAINE_NOM, EVENEMENT_MAJ_PROGRAMMES, vec![Securite::L2Prive])
                .partition(&user_id)
                .build();
            let evenement_programmes = json!({
                CHAMP_UUID_APPAREIL: &transaction_convertie.uuid_appareil,
                "programmes": programmes
            });
            middleware.emettre_evenement(routage_evenement, &evenement_programmes).await?;
        }
    }

    debug!("transaction_sauvegarder_programme Resultat ajout transaction : {:?}", document_transaction);
    Ok(Some(middleware.build_reponse(&document_transaction)?.0))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionInitialiserAppareil {
    pub uuid_appareil: String,
    pub user_id: String,
}

async fn transaction_initialiser_appareil<M>(middleware: &M, transaction: TransactionValide, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao
{
    debug!("transaction_initialiser_appareil Consommer transaction : {:?}", transaction.transaction.id);
    let transaction_convertie: TransactionInitialiserAppareil = serde_json::from_str(transaction.transaction.contenu.as_str())?;

    let collection = middleware.get_collection(COLLECTIONS_APPAREILS)?;

    let filtre = doc! { CHAMP_UUID_APPAREIL: &transaction_convertie.uuid_appareil, CHAMP_USER_ID: &transaction_convertie.user_id };
    let ops = doc! {
        "$set": { "persiste": true },
        "$setOnInsert": {
            CHAMP_UUID_APPAREIL: &transaction_convertie.uuid_appareil,
            CHAMP_USER_ID: &transaction_convertie.user_id,
            CHAMP_CREATION: Utc::now(),
            "present": false,
        },
        "$currentDate": { CHAMP_MODIFICATION: true },
    };
    let options = UpdateOptions::builder().upsert(true).build();
    if let Err(e) = collection.update_one_with_session(filtre, ops, options, session).await {
        Err(format!("transactions.transaction_initialiser_appareil Erreur chargement collection : {:?}", e))?
    }

    Ok(Some(middleware.reponse_ok(None, None)?))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TransactionAppareilSupprimer {
    uuid_appareil: String,
}

async fn transaction_appareil_supprimer<M>(middleware: &M, transaction: TransactionValide, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao
{
    debug!("transaction_appareil_supprimer Consommer transaction : {:?}", transaction.transaction.id);
    let contenu_transaction: TransactionAppareilSupprimer = serde_json::from_str(transaction.transaction.contenu.as_str())?;

    let user_id = match transaction.certificat.get_user_id()? {
        Some(user) => user.to_owned(),
        None => Err(Error::Str("senseurspassifs.transaction_appareil_supprimer Erreur user_id absent du certificat"))?
    };

    let filtre = doc! { CHAMP_USER_ID: &user_id, CHAMP_UUID_APPAREIL: &contenu_transaction.uuid_appareil };
    let collection = middleware.get_collection(COLLECTIONS_APPAREILS)?;
    let ops = doc! {
        "$set": { CHAMP_SUPPRIME: true },
        "$currentDate": { CHAMP_MODIFICATION: true }
    };
    let options = FindOneAndUpdateOptions::builder().return_document(ReturnDocument::After).build();
    let doc_appareil = match collection.find_one_and_update_with_session(filtre, ops, options, session).await {
        Ok(inner) => match inner {
            Some(inner) => {
                let doc_appareil: DocAppareil = match convertir_bson_deserializable(inner) {
                    Ok(inner) => inner,
                    Err(e) => Err(format!("senseurspassifs.transaction_appareil_restaurer Erreur mapping DocAppareil {:?}", e))?
                };
                doc_appareil
            },
            None => Err(format!("senseurspassifs.transaction_appareil_restaurer Appareil {} inconnu", contenu_transaction.uuid_appareil))?
        },
        Err(e) => Err(format!("senseurspassifs.transaction_appareil_restaurer Erreur DB {:?}", e))?
    };

    {
        let routage_evenement = RoutageMessageAction::builder(DOMAINE_NOM, TRANSACTION_MAJ_APPAREIL, vec![Securite::L2Prive])
            .partition(&user_id)
            .build();
        middleware.emettre_evenement(routage_evenement, &doc_appareil).await?;
    }

    Ok(Some(middleware.reponse_ok(None, None)?))
}

async fn transaction_appareil_restaurer<M>(middleware: &M, transaction: TransactionValide, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao
{
    debug!("transaction_appareil_restaurer Consommer transaction : {:?}", transaction.transaction.id);
    let contenu_transaction: TransactionAppareilSupprimer = serde_json::from_str(transaction.transaction.contenu.as_str())?;

    let user_id = match transaction.certificat.get_user_id()? {
        Some(user) => user.to_owned(),
        None => Err(Error::Str("senseurspassifs.transaction_appareil_restaurer Erreur user_id absent du certificat"))?
    };

    let filtre = doc! { CHAMP_USER_ID: &user_id, CHAMP_UUID_APPAREIL: &contenu_transaction.uuid_appareil };
    let collection = middleware.get_collection(COLLECTIONS_APPAREILS)?;
    let ops = doc! {
        "$set": { CHAMP_SUPPRIME: false },
        "$currentDate": { CHAMP_MODIFICATION: true }
    };
    let options = FindOneAndUpdateOptions::builder().return_document(ReturnDocument::After).build();
    let doc_appareil = match collection.find_one_and_update_with_session(filtre, ops, options, session).await {
        Ok(inner) => match inner {
            Some(inner) => {
                let doc_appareil: DocAppareil = match convertir_bson_deserializable(inner) {
                    Ok(inner) => inner,
                    Err(e) => Err(format!("senseurspassifs.transaction_appareil_restaurer Erreur mapping DocAppareil {:?}", e))?
                };
                doc_appareil
            },
            None => Err(format!("senseurspassifs.transaction_appareil_restaurer Appareil {} inconnu", contenu_transaction.uuid_appareil))?
        },
        Err(e) => Err(format!("senseurspassifs.transaction_appareil_restaurer Erreur DB {:?}", e))?
    };

    {
        let routage_evenement = RoutageMessageAction::builder(DOMAINE_NOM, TRANSACTION_MAJ_APPAREIL, vec![Securite::L2Prive])
            .partition(&user_id)
            .build();
        middleware.emettre_evenement(routage_evenement, &doc_appareil).await?;
    }

    Ok(Some(middleware.reponse_ok(None, None)?))
}

async fn transaction_maj_noeud<M>(middleware: &M, transaction: TransactionValide, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where
        M: GenerateurMessages + MongoDao
{
    debug!("transaction_maj_noeud Consommer transaction : {:?}", &transaction.transaction.id);
    let contenu_transaction: TransactionMajNoeud = serde_json::from_str(transaction.transaction.contenu.as_str())?;

    let document_transaction = {
        let mut valeurs = match convertir_to_bson(contenu_transaction.clone()) {
            Ok(v) => v,
            Err(e) => Err(format!("senseurspassifs.transaction_maj_noeud Erreur conversion transaction a bson : {:?}", e))?
        };
        valeurs.remove("instance_id"); // Enlever cle

        let mut ops = doc! {
            "$setOnInsert": {
                CHAMP_CREATION: Utc::now(),
                CHAMP_INSTANCE_ID: &contenu_transaction.instance_id,
            },
            "$currentDate": {CHAMP_MODIFICATION: true}
        };

        if valeurs.len() > 0 {
            ops.insert("$set", valeurs);
        }

        let filtre = doc! { CHAMP_INSTANCE_ID: &contenu_transaction.instance_id };
        let collection = middleware.get_collection(COLLECTIONS_INSTANCES)?;
        let opts = FindOneAndUpdateOptions::builder().upsert(true).return_document(ReturnDocument::After).build();
        match collection.find_one_and_update_with_session(filtre, ops, Some(opts), session).await {
            Ok(r) => {
                match r {
                    Some(r) => {
                        debug!("Conversion document maj recu : {:?}", r);
                        match convertir_bson_deserializable::<TransactionMajNoeud>(r) {
                            Ok(r) => r,
                            Err(e) => Err(format!("senseurspassifs.transaction_maj_noeud Erreur conversion a TransactionMajNoeud : {:?}", e))?
                        }
                    },
                    None => Err(format!("senseurspassifs.transaction_maj_noeud Erreur recuperation document transaction maj"))?
                }
            },
            Err(e) => Err(format!("senseurspassifs.transaction_maj_noeud Erreur traitement transaction senseur : {:?}", e))?
        }
    };

    {
        let routage_evenement = RoutageMessageAction::builder(DOMAINE_NOM, TRANSACTION_MAJ_NOEUD, vec![Securite::L2Prive])
            // .partition(&document_transaction.instance_id)
            .build();
        middleware.emettre_evenement(routage_evenement, &document_transaction).await?;
    }

    debug!("transaction_maj_noeud Resultat ajout transaction : {:?}", document_transaction);
    Ok(Some(middleware.build_reponse(&document_transaction)?.0))
}

async fn transaction_suppression_senseur<M>(middleware: &M, transaction: TransactionValide, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao
{
    debug!("transaction_suppression_senseur Consommer transaction : {:?}", &transaction.transaction.id);
    let contenu_transaction: TransactionSupprimerSenseur = serde_json::from_str(transaction.transaction.contenu.as_str())?;

    {
        let filtre = doc! { CHAMP_UUID_SENSEUR: &contenu_transaction.uuid_senseur };
        let collection = middleware.get_collection(COLLECTIONS_LECTURES)?;
        let resultat = match collection.delete_one_with_session(filtre, None, session).await {
            Ok(r) => r,
            Err(e) => Err(format!("senseurspassifs.transaction_suppression_senseur Erreur traitement transaction senseur : {:?}", e))?
        };
        debug!("transaction_suppression_senseur Resultat suppression senseur : {:?}", resultat);
    }

    Ok(Some(middleware.reponse_ok(None, None)?))
}

async fn transaction_lectures<M>(middleware: &M, transaction: TransactionValide, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("transaction_lectures Consommer transaction : {:?}", transaction.transaction.id);
    let contenu_transaction: TransactionLectures = serde_json::from_str(transaction.transaction.contenu.as_str())?;

    // Trouver la plus recente lecture
    match contenu_transaction.plus_recente_lecture() {
        Some(plus_recente_lecture) => {

            let senseur = doc! {
                "valeur": &plus_recente_lecture.valeur,
                "timestamp": &plus_recente_lecture.timestamp,
                "type": &contenu_transaction.type_,
            };

            let filtre = doc! {
                "user_id": &contenu_transaction.user_id,
                CHAMP_UUID_SENSEUR: &contenu_transaction.uuid_senseur,
                "derniere_lecture": &plus_recente_lecture.timestamp,
            };
            // let filtre = doc! { CHAMP_UUID_SENSEUR: &contenu_transaction.uuid_senseur };
            let collection = middleware.get_collection(COLLECTIONS_LECTURES)?;
            let ops = doc! {
                "$set": {
                    format!("{}.{}", CHAMP_SENSEURS, &contenu_transaction.senseur): senseur,
                    "derniere_lecture": &plus_recente_lecture.timestamp,
                    "derniere_lecture_dt": &plus_recente_lecture.timestamp,
                },
                "$setOnInsert": {
                    CHAMP_CREATION: Utc::now(),
                    CHAMP_INSTANCE_ID: &contenu_transaction.instance_id,
                    CHAMP_UUID_SENSEUR: &contenu_transaction.uuid_senseur,
                    "user_id": &contenu_transaction.user_id,
                },
                "$currentDate": { CHAMP_MODIFICATION: true },
            };
            let opts = UpdateOptions::builder().upsert(true).build();
            let resultat = match collection.update_one_with_session(filtre, ops, Some(opts), session).await {
                Ok(r) => r,
                Err(e) => Err(format!("senseurspassifs.transaction_lectures Erreur traitement transaction senseur : {:?}", e))?
            };
            debug!("transaction_lectures Resultat : {:?}", resultat);

            // Legacy - logique ici n'est plus necessaire, on est toujours en regeneration
            // if middleware.get_mode_regeneration() == false {
            //     if let Some(_) = resultat.upserted_id {
            //         debug!("Creer transaction pour nouveau senseur {}", contenu_transaction.uuid_senseur);
            //         let transaction = TransactionMajSenseur::new(
            //             &contenu_transaction.uuid_senseur, &contenu_transaction.instance_id);
            //         // let routage = RoutageMessageAction::builder(DOMAINE_NOM, TRANSACTION_MAJ_SENSEUR, vec![Securite::L4Secure])
            //         //     .blocking(false)
            //         //     .build();
            //         // middleware.soumettre_transaction(routage, &transaction).await?;
            //         if let Err(e) = sauvegarder_traiter_transaction_serializable_v2(
            //             middleware, &transaction, gestionnaire, DOMAINE_NOM, TRANSACTION_MAJ_SENSEUR).await
            //         {
            //             error!("Erreur sauvegarder_traiter_transaction_serializable pour nouveau senseur : {:?}", e);
            //         }
            //     }
            // }
        },
        None => {
            warn!("Transaction lectures senseur {} recue sans contenu (aucunes lectures)", contenu_transaction.uuid_senseur);
        }
    }

    Ok(Some(middleware.reponse_ok(None, None)?))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TransactionSupprimerSenseur {
    uuid_senseur: String
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TransactionLectures {
    /// Identificateur unique de l'appareil
    uuid_senseur: String,

    /// Identificateur interne du senseur sur l'appareil
    senseur: String,

    /// UUID du noeud MilleGrille
    instance_id: String,

    //// User id (compte)
    user_id: String,

    /// Type de lecture, e.g. temperature, humidite, pression, voltage, batterie, etc.
    #[serde(rename="type")]
    type_: String,

    /// Heure de base des lectures dans la transaction en epoch secs
    #[serde(with="epochseconds")]
    timestamp: DateTime<Utc>,

    /// Moyenne des lectures
    avg: f64,

    /// Valeur max des lectures
    max: f64,

    /// Valeur min des lectures
    min: f64,

    /// Plus vieille date de lecture
    #[serde(with="epochseconds")]
    timestamp_min: DateTime<Utc>,

    /// Plus recente date de lecture
    #[serde(with="epochseconds")]
    timestamp_max: DateTime<Utc>,

    /// Liste des lectures
    lectures: Vec<LectureTransaction>
}

impl TransactionLectures {
    fn plus_recente_lecture(&self) -> Option<LectureTransaction> {
        let mut date_lecture: &DateTime<Utc> = &DateTime::<Utc>::MIN_UTC;
        let mut lecture = None;
        for l in &self.lectures {
            if date_lecture < &l.timestamp {
                lecture = Some(l);
                date_lecture = &l.timestamp;
            }
        }
        match lecture {
            Some(l) => Some(l.to_owned()),
            None => None
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TransactionMajSenseur {
    uuid_senseur: String,
    instance_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    descriptif: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    displays: Option<HashMap<String, ParametresDisplay>>
}

impl TransactionMajSenseur {
    pub fn new<S, U>(uuid_senseur: S, uuid_noeud: U)  -> Self
        where S: Into<String>, U: Into<String>
    {
        TransactionMajSenseur {
            uuid_senseur: uuid_senseur.into(),
            instance_id: uuid_noeud.into(),
            descriptif: None,
            displays: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SenseurHoraireRow {
    #[serde(rename="_mg-creation", with="chrono_datetime_as_bson_datetime")]
    pub creation: DateTime<Utc>,
    pub user_id: String,
    pub uuid_appareil: String,
    pub senseur_id: String,
    #[serde(with="chrono_datetime_as_bson_datetime")]
    pub heure: DateTime<Utc>,
    #[serde(rename="type")]
    pub type_: Option<String>,
    pub min: Option<f64>,
    pub max: Option<f64>,
    pub avg: Option<f64>,
}

impl From<&TransactionLectureHoraire> for SenseurHoraireRow {
    fn from(value: &TransactionLectureHoraire) -> Self {

        let type_ = match value.lectures.get(value.lectures.len()-1) {
            Some(lecture) => Some(lecture.type_.clone()),
            None => None
        };

        Self {
            creation: Utc::now(),
            user_id: value.user_id.clone(),
            uuid_appareil: value.uuid_appareil.clone(),
            senseur_id: value.senseur_id.clone(),
            heure: value.heure,
            type_,
            min: value.min,
            max: value.max,
            avg: value.avg,
        }
    }
}

async fn transaction_senseur_horaire<M>(middleware: &M, transaction: TransactionValide, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao
{
    debug!("transaction_senseur_horaire Consommer transaction : {:?}", transaction.transaction.id);
    let transaction_convertie: TransactionLectureHoraire = serde_json::from_str(transaction.transaction.contenu.as_str())?;
    let senseur_horaire_row = SenseurHoraireRow::from(&transaction_convertie);

    // Inserer dans la table de lectures senseurs horaires
    let collection = middleware.get_collection_typed::<SenseurHoraireRow>(COLLECTIONS_SENSEURS_HORAIRE)?;
    if middleware.get_mode_regeneration() == true {
        // HACK - duplicate transactions have been produced. Remove once all transactions are fixed/migrated
        let filtre = doc!{
            CHAMP_USER_ID: &transaction_convertie.user_id,
            CHAMP_UUID_APPAREIL: &transaction_convertie.uuid_appareil,
            "senseur_id": &transaction_convertie.senseur_id,
            "heure": &transaction_convertie.heure
        };
        let options = FindOneOptions::builder().hint(Hint::Name("lectures_horaire".to_string())).build();
        if collection.find_one_with_session(filtre, options, session).await?.is_some() {
            warn!("transaction_senseur_horaire Ignoring duplicate transaction: {} on rebuild", transaction.transaction.id);
            return Ok(None);
        }
    }

    collection.insert_one_with_session(&senseur_horaire_row, None, session).await?;

    // Other approach - pre-commit (slow)
    // if middleware.get_mode_regeneration() == true {
    //     // Commit previous changes, the following transaction can fail on duplicates.
    //     session.commit_transaction().await?;
    //     start_transaction_regeneration(session).await?;
    // }

    // if let Err(e) = collection.insert_one_with_session(&senseur_horaire_row, None, session).await {
    //     if middleware.get_mode_regeneration() == true {  // Rebuilding
    //         error!("transaction_senseur_horaire Error processing transaction, skipping: {:?}", e);
    //         session.abort_transaction().await?;
    //         start_transaction_regeneration(session).await?;
    //     } else {
    //         Err(e)?  // Re-raise error for standard transaction processing
    //     }
    // }

    // S'assurer que l'appareil existe (e.g. pour regeneration)
    if middleware.get_mode_regeneration() == false {
        let collection = middleware.get_collection(COLLECTIONS_APPAREILS)?;
        let filtre = doc! {
            CHAMP_USER_ID: &transaction_convertie.user_id,
            CHAMP_UUID_APPAREIL: &transaction_convertie.uuid_appareil,
        };
        let mut ops = doc! {
            "$setOnInsert": {
                CHAMP_USER_ID: &transaction_convertie.user_id,
                CHAMP_UUID_APPAREIL: &transaction_convertie.uuid_appareil,
                CHAMP_CREATION: Utc::now(),
                "present": false,
            },
            "$currentDate": {
                CHAMP_MODIFICATION: true,
            },
            "$addToSet": {
                CHAMP_LECTURES_DISPONIBLES: &transaction_convertie.senseur_id
            }
        };

        // Detecter type de lectures (aucun si vide)
        let mut type_donnees = None;
        for l in &transaction_convertie.lectures {
            type_donnees = Some(l.type_.clone());
            break
        }

        if let Some(type_donnees) = type_donnees {
            ops.insert("$set", doc!{
                format!("types_donnees.{}", transaction_convertie.senseur_id): type_donnees
            });
        }

        let options = UpdateOptions::builder().upsert(true).build();
        if let Err(e) = collection.update_one_with_session(filtre, ops, options, session).await {
            Err(format!("transactions.transaction_initialiser_appareil Erreur chargement collection : {:?}", e))?
        }
    }

    Ok(Some(middleware.reponse_ok(None, None)?))
}

#[derive(Serialize, Deserialize)]
pub struct TransactionMajConfigurationUsager {
    timezone: Option<String>,
}

async fn transaction_maj_configuration_usager<M>(middleware: &M, transaction: TransactionValide, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao
{
    debug!("transaction_maj_configuration_usager Consommer transaction : {:?}", transaction.transaction.id);
    let contenu_transaction: TransactionMajConfigurationUsager = serde_json::from_str(transaction.transaction.contenu.as_str())?;

    let user_id = match transaction.certificat.get_user_id()? {
        Some(user) => user.to_owned(),
        None => Err(Error::Str("senseurspassifs.transaction_maj_configuration_usager Erreur user_id absent du certificat"))?
    };

    let filtre = doc!{CHAMP_USER_ID: &user_id};
    let collection = middleware.get_collection(COLLECTIONS_USAGER)?;

    let transaction_bson = match convertir_to_bson(contenu_transaction) {
        Ok(inner) => inner,
        Err(e) => Err(format!("senseurspassifs.transaction_maj_configuration_usager Erreur conversion : {:?}", e))?
    };

    let ops = doc!{
        "$set": transaction_bson,
        "$setOnInsert": {
            CHAMP_USER_ID: &user_id,
            CHAMP_CREATION: Utc::now(),
        },
        "$currentDate": {CHAMP_MODIFICATION: true}
    };
    let options = UpdateOptions::builder().upsert(true).build();
    if let Err(e) = collection.update_one_with_session(filtre, ops, options, session).await {
        Err(format!("senseurspassifs.transaction_maj_configuration_usager Erreur maj configuration : {:?}", e))?
    }

    Ok(Some(middleware.reponse_ok(None, None)?))
}