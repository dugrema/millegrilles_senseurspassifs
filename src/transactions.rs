use std::collections::HashMap;
use log::{debug, error, info, warn};
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::certificats::ValidateurX509;
use millegrilles_common_rust::chrono;
use millegrilles_common_rust::chrono::Utc;
use millegrilles_common_rust::formatteur_messages::{DateEpochSeconds, MessageMilleGrille};
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, convertir_to_bson, filtrer_doc_id, MongoDao};
use millegrilles_common_rust::transactions::Transaction;
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::mongodb::options::{FindOneAndUpdateOptions, ReturnDocument, UpdateOptions};
use millegrilles_common_rust::serde_json::json;
use millegrilles_common_rust::serde::{Deserialize, Serialize};

use crate::common::*;
use crate::senseurspassifs::GestionnaireSenseursPassifs;

pub async fn aiguillage_transaction<M, T>(middleware: &M, transaction: T, gestionnaire: &GestionnaireSenseursPassifs)
    -> Result<Option<MessageMilleGrille>, String>
    where
        M: ValidateurX509 + GenerateurMessages + MongoDao,
        T: Transaction
{
    debug!("aiguillage_transaction {}", transaction.get_action());
    match transaction.get_action() {
        TRANSACTION_MAJ_SENSEUR => transaction_maj_senseur(middleware, transaction, gestionnaire).await,
        TRANSACTION_MAJ_NOEUD => transaction_maj_noeud(middleware, transaction, gestionnaire).await,
        TRANSACTION_SUPPRESSION_SENSEUR => transaction_suppression_senseur(middleware, transaction, gestionnaire).await,
        TRANSACTION_LECTURE => transaction_lectures(middleware, transaction, gestionnaire).await,
        TRANSACTION_MAJ_APPAREIL => transaction_maj_appareil(middleware, transaction, gestionnaire).await,
        TRANSACTION_SENSEUR_HORAIRE => transaction_senseur_horaire(middleware, transaction, gestionnaire).await,
        _ => Err(format!("senseurspassifs.aiguillage_transaction: Transaction {} est de type non gere : {}", transaction.get_uuid_transaction(), transaction.get_action())),
    }
}

async fn transaction_maj_senseur<M, T>(middleware: &M, transaction: T, gestionnaire: &GestionnaireSenseursPassifs)
    -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao,
        T: Transaction
{
    debug!("transaction_maj_senseur Consommer transaction : {:?}", &transaction);
    let transaction_cle = match transaction.clone().convertir::<TransactionMajSenseur>() {
        Ok(t) => t,
        Err(e) => Err(format!("senseurspassifs.transaction_maj_senseur Erreur conversion transaction : {:?}", e))?
    };
    debug!("transaction_maj_senseur Transaction lue {:?}", transaction_cle);

    let user_id = match transaction.get_enveloppe_certificat() {
        Some(inner) => match inner.get_user_id()? {
            Some(user) => user.to_owned(),
            None => Err(format!("senseurspassifs.transaction_maj_senseur Erreur user_id absent du certificat"))?
        },
        None => Err(format!("senseurspassifs.transaction_maj_senseur Erreur certificat absent"))?
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
        match collection.find_one_and_update(filtre, ops, Some(opts)).await {
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
        let resultat = match collection_noeud.update_one(filtre, ops, Some(opts)).await {
            Ok(r) => r,
            Err(e) => Err(format!("senseurspassifs.transaction_maj_senseur Erreur traitement maj noeud : {:?}", e))?
        };

        if let Some(_) = resultat.upserted_id {
            debug!("transaction_maj_senseur Creer transaction pour instance_id {}", transaction_cle.instance_id);
            let transaction = TransactionMajNoeud::new(&transaction_cle.instance_id);
            let routage = RoutageMessageAction::builder(DOMAINE_NOM, TRANSACTION_MAJ_NOEUD)
                .exchanges(vec![Securite::L4Secure])
                // .partition(&gestionnaire.instance_id)
                .build();
            middleware.soumettre_transaction(routage, &transaction, false).await?;
        }
    }

    {
        let routage_evenement = RoutageMessageAction::builder(DOMAINE_NOM, TRANSACTION_MAJ_SENSEUR)
            .exchanges(vec![Securite::L2Prive])
            .partition(&user_id)
            .build();
        middleware.emettre_evenement(routage_evenement, &document_transaction).await?;
    }

    debug!("transaction_maj_senseur Resultat ajout transaction : {:?}", document_transaction);
    let reponse = match middleware.formatter_reponse(&document_transaction, None) {
        Ok(reponse) => Ok(Some(reponse)),
        Err(e) => Err(format!("senseurspassifs.document_transaction Erreur preparation reponse : {:?}", e))
    }?;

    Ok(reponse)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TransactionMajAppareil {
    uuid_appareil: String,
    configuration: ConfigurationAppareil,
}

async fn transaction_maj_appareil<M, T>(middleware: &M, transaction: T, gestionnaire: &GestionnaireSenseursPassifs)
    -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao,
        T: Transaction
{
    debug!("transaction_maj_senseur Consommer transaction : {:?}", &transaction);
    let user_id = match transaction.get_enveloppe_certificat() {
        Some(inner) => match inner.get_user_id()? {
            Some(user) => user.to_owned(),
            None => Err(format!("senseurspassifs.transaction_maj_senseur Erreur user_id absent du certificat"))?
        },
        None => Err(format!("senseurspassifs.transaction_maj_senseur Erreur certificat absent"))?
    };

    let transaction_convertie: TransactionMajAppareil = match transaction.convertir() {
        Ok(t) => t,
        Err(e) => Err(format!("senseurspassifs.transaction_maj_appareil Erreur conversion transaction : {:?}", e))?
    };
    debug!("transaction_maj_appareil Transaction lue {:?}", transaction_convertie);

    let document_transaction: DocAppareil = {
        let mut set_ops = doc! {};

        if let Some(inner) = transaction_convertie.configuration.descriptif {
            set_ops.insert("configuration.descriptif", inner);
        }
        if let Some(inner) = transaction_convertie.configuration.cacher_senseurs {
            set_ops.insert("configuration.cacher_senseurs", inner);
        }
        if let Some(inner) = transaction_convertie.configuration.descriptif_senseurs {
            let bson_map = match convertir_to_bson(inner) {
                Ok(inner) => inner,
                Err(e) => Err(format!("senseurspassifs.transaction_maj_appareil Erreur conversion descriptif_senseurs en bson : {:?}", e))?
            };
            set_ops.insert("configuration.descriptif_senseurs", bson_map);
        }
        if let Some(inner) = transaction_convertie.configuration.displays {
            let bson_map = match convertir_to_bson(inner) {
                Ok(inner) => inner,
                Err(e) => Err(format!("senseurspassifs.transaction_maj_appareil Erreur conversion displays en bson : {:?}", e))?
            };
            set_ops.insert("configuration.displays", bson_map);
        }

        let ops = doc! {
            "$set": set_ops,
            "$setOnInsert": {
                CHAMP_CREATION: Utc::now(),
                CHAMP_UUID_APPAREIL: &transaction_convertie.uuid_appareil,
                CHAMP_USER_ID: &user_id,
            },
            "$currentDate": {CHAMP_MODIFICATION: true}
        };

        let filtre = doc! { CHAMP_UUID_APPAREIL: &transaction_convertie.uuid_appareil, CHAMP_USER_ID: &user_id };
        let opts = FindOneAndUpdateOptions::builder()
            .upsert(true)
            .return_document(ReturnDocument::After)
            .build();

        let collection = middleware.get_collection(COLLECTIONS_APPAREILS)?;
        match collection.find_one_and_update(filtre, ops, Some(opts)).await {
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
        let routage_evenement = RoutageMessageAction::builder(DOMAINE_NOM, TRANSACTION_MAJ_APPAREIL)
            .exchanges(vec![Securite::L2Prive])
            .partition(&user_id)
            .build();
        middleware.emettre_evenement(routage_evenement, &document_transaction).await?;
    }

    // Evenement de mise a jour des displays (relais)
    if let Some(configuration) = &document_transaction.configuration {
        if let Some(displays) = &configuration.displays {
            let routage_evenement = RoutageMessageAction::builder(DOMAINE_NOM, EVENEMENT_MAJ_DISPLAYS)
                .exchanges(vec![Securite::L2Prive])
                .partition(&user_id)
                .build();
            let evenement_displays = json!({
                CHAMP_UUID_APPAREIL: &transaction_convertie.uuid_appareil,
                "displays": displays
            });
            middleware.emettre_evenement(routage_evenement, &evenement_displays).await?;
        }
    }

    debug!("transaction_maj_appareil Resultat ajout transaction : {:?}", document_transaction);
    let reponse = match middleware.formatter_reponse(&document_transaction, None) {
        Ok(reponse) => Ok(Some(reponse)),
        Err(e) => Err(format!("senseurspassifs.transaction_maj_appareil Erreur preparation reponse : {:?}", e))
    }?;

    Ok(reponse)
}

async fn transaction_maj_noeud<M, T>(middleware: &M, transaction: T, gestionnaire: &GestionnaireSenseursPassifs)
    -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao,
        T: Transaction
{
    debug!("transaction_maj_noeud Consommer transaction : {:?}", &transaction);
    let contenu_transaction = match transaction.clone().convertir::<TransactionMajNoeud>() {
        Ok(t) => t,
        Err(e) => Err(format!("senseurspassifs.transaction_maj_noeud Erreur conversion transaction : {:?}", e))?
    };
    debug!("transaction_maj_noeud Transaction lue {:?}", contenu_transaction);

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
        match collection.find_one_and_update(filtre, ops, Some(opts)).await {
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
        let routage_evenement = RoutageMessageAction::builder(DOMAINE_NOM, TRANSACTION_MAJ_NOEUD)
            .exchanges(vec![Securite::L2Prive])
            // .partition(&document_transaction.instance_id)
            .build();
        middleware.emettre_evenement(routage_evenement, &document_transaction).await?;
    }

    debug!("transaction_maj_noeud Resultat ajout transaction : {:?}", document_transaction);
    match middleware.formatter_reponse(&document_transaction, None) {
        Ok(reponse) => Ok(Some(reponse)),
        Err(e) => Err(format!("senseurspassifs.transaction_maj_noeud Erreur preparation reponse : {:?}", e))
    }
}

async fn transaction_suppression_senseur<M, T>(middleware: &M, transaction: T, gestionnaire: &GestionnaireSenseursPassifs)
    -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao,
        T: Transaction
{
    debug!("transaction_suppression_senseur Consommer transaction : {:?}", &transaction);
    let contenu_transaction = match transaction.clone().convertir::<TransactionSupprimerSenseur>() {
        Ok(t) => t,
        Err(e) => Err(format!("senseurspassifs.transaction_suppression_senseur Erreur conversion transaction : {:?}", e))?
    };
    debug!("transaction_suppression_senseur Transaction lue {:?}", contenu_transaction);

    {
        let filtre = doc! { CHAMP_UUID_SENSEUR: &contenu_transaction.uuid_senseur };
        let collection = middleware.get_collection(COLLECTIONS_LECTURES)?;
        let resultat = match collection.delete_one(filtre, None).await {
            Ok(r) => r,
            Err(e) => Err(format!("senseurspassifs.transaction_suppression_senseur Erreur traitement transaction senseur : {:?}", e))?
        };
        debug!("transaction_suppression_senseur Resultat suppression senseur : {:?}", resultat);
    }

    middleware.reponse_ok()
}

async fn transaction_lectures<M, T>(middleware: &M, transaction: T, gestionnaire: &GestionnaireSenseursPassifs)
    -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao,
        T: Transaction
{
    debug!("transaction_lectures Consommer transaction : {:?}", &transaction);
    let contenu_transaction = match transaction.clone().convertir::<TransactionLectures>() {
        Ok(t) => t,
        Err(e) => Err(format!("senseurspassifs.transaction_lectures Erreur conversion transaction : {:?}", e))?
    };
    debug!("transaction_lectures Transaction lue {:?}", contenu_transaction);

    // Trouver la plus recente lecture
    match contenu_transaction.plus_recente_lecture() {
        Some(plus_recente_lecture) => {

            let senseur = doc! {
                "valeur": &plus_recente_lecture.valeur,
                "timestamp": &plus_recente_lecture.timestamp,
                "type": &contenu_transaction.type_,
            };

            let filtre = doc! {
                CHAMP_UUID_SENSEUR: &contenu_transaction.uuid_senseur,
                "derniere_lecture": &plus_recente_lecture.timestamp,
                "user_id": &contenu_transaction.user_id,
            };
            let filtre = doc! { CHAMP_UUID_SENSEUR: &contenu_transaction.uuid_senseur };
            let collection = middleware.get_collection(COLLECTIONS_LECTURES)?;
            let ops = doc! {
                "$set": {
                    format!("{}.{}", CHAMP_SENSEURS, &contenu_transaction.senseur): senseur,
                    "derniere_lecture": &plus_recente_lecture.timestamp,
                    "derniere_lecture_dt": &plus_recente_lecture.timestamp.get_datetime(),
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
            let resultat = match collection.update_one(filtre, ops, Some(opts)).await {
                Ok(r) => r,
                Err(e) => Err(format!("senseurspassifs.transaction_lectures Erreur traitement transaction senseur : {:?}", e))?
            };
            debug!("transaction_lectures Resultat : {:?}", resultat);

            if let Some(_) = resultat.upserted_id {
                debug!("Creer transaction pour nouveau senseur {}", contenu_transaction.uuid_senseur);
                let transaction = TransactionMajSenseur::new(
                    &contenu_transaction.uuid_senseur, &contenu_transaction.instance_id);
                let routage = RoutageMessageAction::builder(DOMAINE_NOM, TRANSACTION_MAJ_SENSEUR)
                    .exchanges(vec![Securite::L4Secure])
                    // .partition(&gestionnaire.instance_id)
                    .build();
                middleware.soumettre_transaction(routage, &transaction, false).await?;
            }
        },
        None => {
            warn!("Transaction lectures senseur {} recue sans contenu (aucunes lectures)", contenu_transaction.uuid_senseur);
        }
    }

    middleware.reponse_ok()
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
    timestamp: DateEpochSeconds,

    /// Moyenne des lectures
    avg: f64,

    /// Valeur max des lectures
    max: f64,

    /// Valeur min des lectures
    min: f64,

    /// Plus vieille date de lecture
    timestamp_min: DateEpochSeconds,

    /// Plus recente date de lecture
    timestamp_max: DateEpochSeconds,

    /// Liste des lectures
    lectures: Vec<LectureTransaction>
}

impl TransactionLectures {
    fn plus_recente_lecture(&self) -> Option<LectureTransaction> {
        let mut date_lecture: &chrono::DateTime<Utc> = &chrono::MIN_DATETIME;
        let mut lecture = None;
        for l in &self.lectures {
            if date_lecture < l.timestamp.get_datetime() {
                lecture = Some(l);
                date_lecture = l.timestamp.get_datetime();
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

async fn transaction_senseur_horaire<M, T>(middleware: &M, transaction: T, gestionnaire: &GestionnaireSenseursPassifs)
    -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao,
        T: Transaction
{
    debug!("transaction_senseur_horaire Consommer transaction : {:?}", &transaction);
    let transaction_convertie: TransactionLectureHoraire = match transaction.convertir() {
        Ok(t) => t,
        Err(e) => Err(format!("senseurspassifs.transaction_senseur_horaire Erreur conversion transaction : {:?}", e))?
    };
    debug!("transaction_senseur_horaire Transaction lue {:?}", transaction_convertie);

    // Inserer dans la table de lectures senseurs horaires
    {
        let now = Utc::now();
        let mut doc_insert = doc! {
            CHAMP_CREATION: &now,
            CHAMP_USER_ID: &transaction_convertie.user_id,
            CHAMP_UUID_APPAREIL: &transaction_convertie.uuid_appareil,
            "senseur_id": &transaction_convertie.senseur_id,
            "heure": &transaction_convertie.heure,
        };

        if let Some(v) = transaction_convertie.min {
            doc_insert.insert("min", v);
        }
        if let Some(v) = transaction_convertie.max {
            doc_insert.insert("max", v);
        }
        if let Some(v) = transaction_convertie.avg {
            doc_insert.insert("avg", v);
        }

        let collection = middleware.get_collection(COLLECTIONS_SENSEURS_HORAIRE)?;
        match collection.insert_one(doc_insert, None).await {
            Ok(_) => (),
            Err(e) => {
                warn!("transaction_senseur_horaire Erreur insertion senseurs horaire : {:?}", e)
            }
        }
    }

    // Cleanup table lectures
    let heure_max = transaction_convertie.heure.get_datetime().to_owned() + chrono::Duration::hours(1);
    let filtre = doc! {
        CHAMP_USER_ID: &transaction_convertie.user_id,
        CHAMP_UUID_APPAREIL: &transaction_convertie.uuid_appareil,
        "senseur_id": &transaction_convertie.senseur_id,
    };
    let ops = doc! {
        "$set": {"derniere_aggregation": heure_max},
        "$pull": {"lectures": {"timestamp": {"$gte": &transaction_convertie.heure.get_datetime().timestamp(), "$lt": heure_max.timestamp()}}},
        "$currentDate": {CHAMP_MODIFICATION: true},
    };
    debug!("transaction_senseur_horaire nettoyage lectures filtre {:?}, ops {:?}", filtre, ops);
    let collection = middleware.get_collection(COLLECTIONS_LECTURES)?;
    match collection.update_many(filtre, ops, None).await {
        Ok(result) => {
            if result.modified_count != 1 {
                info!("transaction_senseur_horaire Aucune modification dans table lectures");
            }
        },
        Err(e) => Err(format!("transactions.transaction_senseur_horaire Erreur update_many : {:?}", e))?
    }

    middleware.reponse_ok()
}
