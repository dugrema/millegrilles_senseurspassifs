use log::{debug, info, error};
use millegrilles_common_rust::bson::{doc, Document};

use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::certificats::{calculer_fingerprint, charger_certificat, ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::middleware::{sauvegarder_traiter_transaction, sauvegarder_traiter_transaction_serializable, sauvegarder_traiter_transaction_serializable_v2, sauvegarder_traiter_transaction_v2};
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, MongoDao};
use millegrilles_common_rust::mongodb::options::{FindOneAndUpdateOptions, ReturnDocument, UpdateOptions};
use millegrilles_common_rust::recepteur_messages::{MessageValide, TypeMessage};
use millegrilles_common_rust::serde_json::json;
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::error::Error;
use millegrilles_common_rust::get_domaine_action;
use millegrilles_common_rust::millegrilles_cryptographie::deser_message_buffer;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::rabbitmq_dao::TypeMessageOut;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::{epochseconds, optionepochseconds};
use millegrilles_common_rust::mongodb::ClientSession;
use crate::common::*;
use crate::domain_manager::SenseursPassifsDomainManager;
use crate::evenements::EvenementPresenceAppareilUser;
use crate::transactions::{TransactionInitialiserAppareil, TransactionMajConfigurationUsager, TransactionShowHideSensor};

pub async fn consommer_commande<M>(middleware: &M, m: MessageValide, gestionnaire: &SenseursPassifsDomainManager)
                                   -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("consommer_commande : {:?}", &m.type_message);

    let user_id = m.certificat.get_user_id()?;

    // Autorisation : doit etre un message via exchange
    if user_id.is_none() &&
        ! m.certificat.verifier_exchanges(vec!(Securite::L1Public, Securite::L2Prive, Securite::L3Protege, Securite::L4Secure))? &&
        ! m.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
            Err(format!("senseurspassifs.consommer_commande: Commande autorisation invalide pour message {:?}", m.type_message))?
    }

    let (_, action) = get_domaine_action!(m.type_message);

    let mut session = middleware.get_session().await?;
    session.start_transaction(None).await?;

    let result = match action.as_str() {
        COMMANDE_INSCRIRE_APPAREIL => commande_inscrire_appareil(middleware, m, gestionnaire, &mut session).await,
        COMMANDE_CHALLENGE_APPAREIL => commande_challenge_appareil(middleware, m, gestionnaire, &mut session).await,
        COMMANDE_SIGNER_APPAREIL => commande_signer_appareil(middleware, m, gestionnaire, &mut session).await,
        COMMANDE_CONFIRMER_RELAI => commande_confirmer_relai(middleware, m,  &mut session).await,
        COMMANDE_RESET_CERTIFICATS => commande_reset_certificats(middleware, m, &mut session).await,
        COMMAND_DISCONNECT_RELAY => command_disconnect_relay(middleware, m, &mut session).await,
        TRANSACTION_MAJ_CONFIGURATION_USAGER => commande_maj_configuration_usager(middleware, m, gestionnaire, &mut session).await,
        TRANSACTION_MAJ_SENSEUR |
        TRANSACTION_MAJ_NOEUD |
        TRANSACTION_SUPPRESSION_SENSEUR |
        TRANSACTION_MAJ_APPAREIL => {
            // Pour l'instant, aucune autre validation. On traite comme une transaction
            Ok(sauvegarder_traiter_transaction_v2(middleware, m, gestionnaire, &mut session).await?)
        }
        TRANSACTION_APPAREIL_SUPPRIMER |
        TRANSACTION_APPAREIL_RESTAURER |
        TRANSACTION_SAUVEGARDER_PROGRAMME => {
            if user_id.is_none() {
                Err(format!("senseurspassifs.consommer_commande: Commande autorisation invalide (user_id requis) pour message {:?}", m.type_message))?
            }
            // Pour l'instant, aucune autre validation. On traite comme une transaction
            Ok(sauvegarder_traiter_transaction_v2(middleware, m, gestionnaire, &mut session).await?)
        }
        TRANSACTION_SHOW_HIDE_SENSOR => command_show_hide_sensor(middleware, m, gestionnaire, &mut session).await,
        _ => Err(format!("senseurspassifs.consommer_commande: Commande {} inconnue : {}, message dropped", DOMAINE_NOM, action))?,
    };

    match result {
        Ok(inner) => {
            session.commit_transaction().await?;
            Ok(inner)
        },
        Err(e) => {
            session.abort_transaction().await?;
            Err(e)
        },
    }
}

async fn commande_inscrire_appareil<M>(middleware: &M, m: MessageValide, gestionnaire: &SenseursPassifsDomainManager, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao
{
    debug!("commande_inscrire_appareil Consommer requete : {:?}", & m.type_message);
    let mut commande: CommandeInscrireAppareil = deser_message_buffer!(m.message);

    let collection = middleware.get_collection(COLLECTIONS_APPAREILS)?;
    let filtre_appareil = doc! {
        "uuid_appareil": &commande.uuid_appareil,
        "user_id": &commande.user_id,
    };

    let doc_appareil_option = {
        // Creer appareil au besoin, mettre a jour instance_id
        let set_on_insert = doc! {
            CHAMP_CREATION: Utc::now(),
            CHAMP_MODIFICATION: Utc::now(),
            "user_id": &commande.user_id,
            "uuid_appareil": &commande.uuid_appareil,
        };
        let set = doc! {
            "instance_id": &commande.instance_id,
            // "cle_publique": &commande.cle_publique,
            // "csr": &commande.csr,
        };
        let options = FindOneAndUpdateOptions::builder()
            .upsert(true)
            .return_document(ReturnDocument::After)
            .build();
        let ops = doc! {
            "$setOnInsert": set_on_insert,
            "$set": set,
        };
        collection.find_one_and_update_with_session(filtre_appareil.clone(), ops, Some(options), session).await?
    };

    let doc_appareil: DocAppareil = match doc_appareil_option {
        Some(inner) => convertir_bson_deserializable(inner)?,
        None => {
            Err(format!("Erreur creation document appareil, pas sauvegarde dans DB."))?
        }
    };

    // Appareil existe deja, verifier si le certificat recu est deja signe
    let mut certificat = doc_appareil.certificat;

    match certificat {
        Some(c) => {
            let mut repondre_certificat = false;

            // Comparer cles publiques - si differentes, on genere un nouveau certificat
            if let Some(cle_publique_db) = doc_appareil.cle_publique.as_ref() {
                if &commande.cle_publique != cle_publique_db {
                    // Mismatch CSR et certificat, conserver le csr recu
                    debug!("commande_inscrire_appareil Reset certificat, demande avec nouveau CSR");

                    // certificat = None;
                    // let ops = doc! {
                    //     "$set": {
                    //         "cle_publique": &commande.cle_publique,
                    //         "csr": &commande.csr,
                    //     },
                    //     "$unset": {"certificat": true, "fingerprint": true},
                    //     "$currentDate": {CHAMP_MODIFICATION: true},
                    // };
                    // collection.update_one(filtre_appareil.clone(), ops, None).await?;
                } else {
                    repondre_certificat = true;
                }
            } else {
                repondre_certificat = true;
            }

            if repondre_certificat {
                debug!("Repondre avec le certificat");
                let reponse = json!({"ok": true, "certificat": c});
                return Ok(Some(middleware.build_reponse(reponse)?.0));
            }
        },
        None => {
            // Par de certificat. Conserver le csr recu.
        }
    }

    debug!("commande_inscrire_appareil Reset certificat, demande avec nouveau CSR");
    certificat = None;
    let ops = doc! {
        "$set": {
            "cle_publique": &commande.cle_publique,
            "csr": &commande.csr,
        },
        "$unset": {"certificat": true, "fingerprint": true},
        "$currentDate": {CHAMP_MODIFICATION: true},
    };
    collection.update_one_with_session(filtre_appareil.clone(), ops, None, session).await?;

    // let reponse = json!({"ok": true});
    // return Ok(Some(middleware.formatter_reponse(reponse, None)?));
    Ok(Some(middleware.reponse_ok(None, None)?))
}

async fn commande_signer_appareil<M>(middleware: &M, m: MessageValide, gestionnaire: &SenseursPassifsDomainManager, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + ValidateurX509 + MongoDao
{
    debug!("commande_signer_appareil Consommer requete : {:?}", & m.type_message);
    let mut commande: CommandeSignerAppareil = deser_message_buffer!(m.message);

    let user_id = match m.certificat.get_user_id()? {
        Some(inner) => inner,
        None => {
            // let reponse = json!({"ok": false, "err": "user_id manquant"});
            // return Ok(Some(middleware.formatter_reponse(&reponse, None)?));
            return Ok(Some(middleware.reponse_err(None, None, Some("user_id manquant"))?))
        }
    };

    let collection = middleware.get_collection(COLLECTIONS_APPAREILS)?;

    let mut renouvellement = false;
    if let Some(csr) = commande.csr.as_ref() {
        if let Some(cn) = m.certificat.subject()?.get("commonName") {
            if commande.uuid_appareil.as_str() == cn.as_str() {
                debug!("Renouvellement d'un certificat d'appareil valide pour {}", cn);
                renouvellement = true;
            }
        }
    }

    let filtre_appareil = doc! {
        "uuid_appareil": &commande.uuid_appareil,
        "user_id": &user_id,
    };

    let mut doc_appareil = {
        let d = collection.find_one_with_session(filtre_appareil.clone(), None, session).await?;
        match d {
            Some(d) => {
                let doc_appareil: DocAppareil = convertir_bson_deserializable(d)?;
                doc_appareil
            },
            None => {
                // let reponse = json!({"ok": false, "err": "appareil inconnu"});
                // return Ok(Some(middleware.formatter_reponse(&reponse, None)?));
                return Ok(Some(middleware.reponse_err(None, None, Some("appareil inconnu"))?))
            }
        }
    };

    let certificat = match renouvellement {
        true => signer_certificat(middleware, user_id.as_str(), filtre_appareil, doc_appareil.clone(), commande.csr.as_ref(), session).await?,
        false => match doc_appareil.certificat {
            Some(c) => c,
            None => {
                signer_certificat(middleware, user_id.as_str(), filtre_appareil, doc_appareil.clone(), None, session).await?
            }
        }
    };

    if let Some(true) = doc_appareil.persiste {
        // Ok
        debug!("commande_signer_appareil Transaction appareil deja persiste (OK)")
    } else {
        debug!("commande_signer_appareil Generer transaction pour persister l'appareil {:?}", doc_appareil.uuid_appareil);
        let transaction = TransactionInitialiserAppareil {
            uuid_appareil: doc_appareil.uuid_appareil.to_owned(),
            user_id,
        };
        sauvegarder_traiter_transaction_serializable_v2(
            middleware, &transaction, gestionnaire, session,
            DOMAINE_NOM, TRANSACTION_INIT_APPAREIL).await?;
    }

    debug!("Repondre avec certificat");
    let reponse = json!({
        "ok": true,
        "certificat": certificat,
    });

    Ok(Some(middleware.build_reponse(reponse)?.0))
}

async fn commande_maj_configuration_usager<M>(middleware: &M, m: MessageValide, gestionnaire: &SenseursPassifsDomainManager, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + ValidateurX509 + MongoDao
{
    debug!("commande_maj_configuration_usager Consommer requete : {:?}", m.type_message);
    // Valider format de la commande
    let _commande: TransactionMajConfigurationUsager = deser_message_buffer!(m.message);

    // Verifier qu'on a un certificat usager
    if m.certificat.get_user_id()?.is_none() {
        return Ok(Some(middleware.reponse_err(None, None, Some("user_id manquant"))?))
    };

    Ok(sauvegarder_traiter_transaction_v2(middleware, m, gestionnaire, session).await?)
}

async fn command_show_hide_sensor<M>(middleware: &M, m: MessageValide, gestionnaire: &SenseursPassifsDomainManager, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + ValidateurX509 + MongoDao
{
    debug!("command_show_hide_sensor Consommer requete : {:?}", m.type_message);
    // Valider format de la commande
    let _commande: TransactionShowHideSensor = deser_message_buffer!(m.message);

    // Verifier qu'on a un certificat usager
    if m.certificat.get_user_id()?.is_none() {
        return Ok(Some(middleware.reponse_err(None, None, Some("user_id manquant"))?))
    };

    Ok(sauvegarder_traiter_transaction_v2(middleware, m, gestionnaire, session).await?)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CommandeInscrireAppareil {
    uuid_appareil: String,
    instance_id: String,
    user_id: String,
    cle_publique: String,
    csr: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CommandeSignerAppareil {
    uuid_appareil: String,
    csr: Option<String>,
}

async fn commande_challenge_appareil<M>(middleware: &M, m: MessageValide, gestionnaire: &SenseursPassifsDomainManager, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao
{
    debug!("commande_challenge_appareil Consommer requete : {:?}", m.type_message);
    let mut commande: CommandeChallengeAppareil = deser_message_buffer!(m.message);

    let user_id = match m.certificat.get_user_id()? {
        Some(inner) => inner,
        None => {
            // let reponse = json!({"ok": false, "err": "user_id manquant"});
            // return Ok(Some(middleware.formatter_reponse(&reponse, None)?));
            return Ok(Some(middleware.reponse_err(None, None, Some("user_id manquant"))?))
        }
    };

    let collection = middleware.get_collection(COLLECTIONS_APPAREILS)?;

    let doc_appareil_option = {
        let filtre = doc! {"uuid_appareil": &commande.uuid_appareil, "user_id": user_id};
        collection.find_one_with_session(filtre, None, session).await?
    };

    let doc_appareil: DocAppareil = match doc_appareil_option {
        Some(d) => convertir_bson_deserializable(d)?,
        None => {
            // let reponse = json!({"ok": false, "err": "Appareil inconnu"});
            // return Ok(Some(middleware.formatter_reponse(&reponse, None)?));
            return Ok(Some(middleware.reponse_err(None, None, Some("Appareil inconnu"))?))
        }
    };

    let instance_id = match doc_appareil.instance_id {
        Some(inner) => inner,
        None => {
            // let reponse = json!({"ok": false, "err": "Pas d'instance_id pour cet appareil"});
            // return Ok(Some(middleware.formatter_reponse(reponse, None)?))
            return Ok(Some(middleware.reponse_err(None, None, Some("Pas d'instance_id pour cet appareil"))?))
        }
    };

    // Emettre la commande de challenge
    let message_challenge = json!({
        "ok": true,
        "uuid_appareil": &commande.uuid_appareil,
        "challenge": &commande.challenge,
        "cle_publique": doc_appareil.cle_publique,
        "fingerprint": doc_appareil.fingerprint,
    });
    let routage = RoutageMessageAction::builder("senseurspassifs_relai", "challengeAppareil", vec![Securite::L2Prive])
        .partition(instance_id)
        .blocking(false)
        .build();
    middleware.transmettre_commande(routage, &message_challenge).await?;

    Ok(Some(middleware.reponse_ok(None, None)?))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CommandeChallengeAppareil {
    uuid_appareil: String,
    challenge: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CommandeConfirmerRelai {
    fingerprint: String,
    #[serde(default, with="optionepochseconds")]
    expiration: Option<DateTime<Utc>>,
}

#[derive(Deserialize)]
pub struct RowRelais {
    pub fingerprint: String,
    pub user_id: String,
    #[serde(default, with="optionepochseconds")]
    pub expiration: Option<DateTime<Utc>>,
}

async fn commande_confirmer_relai<M>(middleware: &M, m: MessageValide, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao
{
    debug ! ("commande_confirmer_relai Consommer requete : {:?}", m.type_message);
    let mut commande: CommandeConfirmerRelai = deser_message_buffer!(m.message);

    let certificat = m.certificat.as_ref();
    let common_name = certificat.get_common_name()?;
    let user_id = match certificat.get_user_id()? {
        Some(inner) => inner,
        None => Err(Error::Str("commande_confirmer_relai Certificat sans user_id"))?
    };

    let filtre = doc! { "uuid_appareil": &common_name, "user_id": &user_id };
    let ops = doc! {
        "$set": { "fingerprint": &commande.fingerprint },
        "$setOnInsert": {
            "uuid_appareil": common_name,
            "user_id": user_id,
            CHAMP_CREATION: Utc::now()
        },
        "$currentDate": { CHAMP_MODIFICATION: true }
    };
    let collection = middleware.get_collection(COLLECTIONS_RELAIS)?;
    let options = UpdateOptions::builder().upsert(true).build();
    collection.update_one_with_session(filtre, ops, options, session).await?;

    Ok(Some(middleware.reponse_ok(None, None)?))
}

async fn signer_certificat<M>(middleware: &M, user_id: &str, filtre_appareil: Document, doc_appareil: DocAppareil, csr_inclus: Option<&String>, session: &mut ClientSession)
    -> Result<Vec<String>, Error>
    where M: GenerateurMessages + MongoDao
{
    let csr = match csr_inclus {
        Some(c) => c.to_owned(),
        None => match doc_appareil.csr {
            Some(c) => c,
            None => {
                Err(format!("senseurspassifs.signer_certificat CSR absent"))?
            }
        }
    };

    debug!("signer_certificat Aucun certificat, faire demande de signature");
    let routage = RoutageMessageAction::builder("CorePki", "signerCsr", vec![Securite::L1Public])
        .build();
    let requete = json!({
        "csr": csr,  // &doc_appareil.csr,
        "roles": ["senseurspassifs"],
        "user_id": user_id,
    });

    debug!("signer_certificat Requete demande signer appareil : {:?}", requete);
    let reponse: ReponseCertificat = match middleware.transmettre_commande(routage, &requete).await? {
        Some(r) => match r {
            TypeMessage::Valide(m) => deser_message_buffer!(m.message),
            _ => Err(Error::Str("senseurspassifs.signer_certificat Reponse certissuer invalide"))?
        },
        None => Err(Error::Str("senseurspassifs.signer_certificat Aucune reponse"))?
    };

    debug!("signer_certificat Reponse : {:?}", reponse);
    if let Some(true) = reponse.ok {
        let (certificat, fingerprint) = match &reponse.certificat {
            Some(c) => {
                let cert_x509 = charger_certificat(c[0].as_str())?;
                (c.to_owned(), calculer_fingerprint(&cert_x509)?)
            },
            None => Err(Error::Str("senseurspassifs.signer_certificat Reponse serveur incorrect (cert)"))?
        };

        let ops = doc! {
            "$set": {
                "certificat": &reponse.certificat,
                "fingerprint": fingerprint,
            },
            "$unset": {"csr": true},
            "$currentDate": {CHAMP_MODIFICATION: true, "certificat_signature_date": true},
        };

        let collection = middleware.get_collection(COLLECTIONS_APPAREILS)?;
        collection.update_one_with_session(filtre_appareil, ops, None, session).await?;

        Ok(certificat)  // Retourner certificat via reponse
    } else {
        Err(Error::Str("senseurspassifs.signer_certificat Reponse serveur incorrect (ok=false)"))?
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ReponseCertificat {
    ok: Option<bool>,
    certificat: Option<Vec<String>>,
}

#[derive(Serialize)]
struct ReponseCommandeResetCertificat {
    ok: bool,
    err: Option<String>,
}

async fn commande_reset_certificats<M>(middleware: &M, m: MessageValide, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao
{
    if ! (m.certificat.verifier_roles(vec![RolesCertificats::ComptePrive])? || m.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)?) {
        // let reponse = middleware.formatter_reponse(ReponseCommandeResetCertificat{ok: false, err: Some("Acces refuse".to_string())}, None)?;
        // return Ok(Some(reponse))
        return Ok(Some(middleware.reponse_err(None, None, Some("Acces refuse"))?))
    }

    let certificat = m.certificat.as_ref();

    let user_id = match certificat.get_user_id()? {
        Some(inner) => inner,
        None => Err("commande_reset_certificats Certificat sans user_id".to_string())?
    };

    let filtre = doc!{ CHAMP_USER_ID: user_id };
    let collection = middleware.get_collection(COLLECTIONS_APPAREILS)?;
    let ops = doc! {
        "$unset": {TRANSACTION_CHAMP_CERTIFICAT: true, PKI_DOCUMENT_CHAMP_FINGERPRINT: true},
        "$currentDate": {CHAMP_MODIFICATION: true}
    };
    collection.update_many_with_session(filtre, ops, None, session).await?;

    // let reponse = middleware.formatter_reponse(ReponseCommandeResetCertificat{ok: true, err: None}, None)?;
    // Ok(Some(reponse))
    Ok(Some(middleware.reponse_ok(None, None)?))
}

pub async fn command_disconnect_relay<M>(middleware: &M, m: MessageValide, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao
{
    if !(m.certificat.verifier_roles_string(vec!["senseurspassifs_relai".to_string()])?) {
        return Ok(Some(middleware.reponse_err(Some(403), None, Some("Acces refuse"))?))
    }
    if !(m.certificat.verifier_exchanges(vec![Securite::L2Prive])?) {
        return Ok(Some(middleware.reponse_err(Some(403), None, Some("Acces refuse"))?))
    }

    let instance_id = m.certificat.get_common_name()?;

    let collection = middleware.get_collection_typed::<DocAppareil>(COLLECTIONS_APPAREILS)?;
    let filtre = doc!{ "instance_id": &instance_id, "connecte": true };
    let mut cursor = collection.find_with_session(filtre, None, session).await?;
    while cursor.advance(session).await? {
        let device = cursor.deserialize_current()?;

        // Emit event for device
        {
            if let Some(user_id) = device.user_id {
                let evenement_reemis = EvenementPresenceAppareilUser {
                    uuid_appareil: device.uuid_appareil,
                    user_id,
                    version: device.version,
                    connecte: false
                };
                let routage = RoutageMessageAction::builder(DOMAINE_NOM, "presenceAppareil", vec![Securite::L2Prive])
                    .partition(&evenement_reemis.user_id)
                    .build();
                middleware.emettre_evenement(routage, &evenement_reemis).await?;
            }
        }
    }

    let ops = doc! {
        "$unset": {"instance_id": true},
        "$set": {"connecte": false},
        "$currentDate": {CHAMP_MODIFICATION: true},
    };
    let filtre = doc!{ "instance_id": instance_id, "connecte": true };
    collection.update_many_with_session(filtre, ops, None, session).await?;

    Ok(Some(middleware.reponse_ok(None, None)?))
}
