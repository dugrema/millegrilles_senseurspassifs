use std::error::Error;
use log::{debug, info, error};
use millegrilles_common_rust::bson::{doc, Document};

use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::certificats::{calculer_fingerprint, charger_certificat, ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chrono::Utc;
use millegrilles_common_rust::formatteur_messages::{DateEpochSeconds, MessageMilleGrille};
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::middleware::{sauvegarder_traiter_transaction, sauvegarder_traiter_transaction_serializable};
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, MongoDao};
use millegrilles_common_rust::mongodb::options::{FindOneAndUpdateOptions, ReturnDocument, UpdateOptions};
use millegrilles_common_rust::recepteur_messages::{MessageValideAction, TypeMessage};
use millegrilles_common_rust::serde_json::json;
use millegrilles_common_rust::verificateur::VerificateurMessage;
use millegrilles_common_rust::serde::{Deserialize, Serialize};

use crate::common::*;
use crate::senseurspassifs::GestionnaireSenseursPassifs;
use crate::transactions::{TransactionInitialiserAppareil, TransactionMajConfigurationUsager};

pub async fn consommer_commande<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireSenseursPassifs)
                                   -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao + VerificateurMessage
{
    debug!("consommer_commande : {:?}", &m.message);

    let user_id = m.get_user_id();

    // Autorisation : doit etre un message via exchange
    if user_id.is_none() &&
        ! m.verifier_exchanges(vec!(Securite::L1Public, Securite::L2Prive, Securite::L3Protege, Securite::L4Secure)) &&
        ! m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
            Err(format!("senseurspassifs.consommer_commande: Commande autorisation invalide pour message {:?}", m.correlation_id))?
    }

    match m.action.as_str() {
        COMMANDE_INSCRIRE_APPAREIL => commande_inscrire_appareil(middleware, m, gestionnaire).await,
        COMMANDE_CHALLENGE_APPAREIL => commande_challenge_appareil(middleware, m, gestionnaire).await,
        COMMANDE_SIGNER_APPAREIL => commande_signer_appareil(middleware, m, gestionnaire).await,
        COMMANDE_CONFIRMER_RELAI => commande_confirmer_relai(middleware, m, gestionnaire).await,
        COMMANDE_RESET_CERTIFICATS => commande_reset_certificats(middleware, m, gestionnaire).await,
        TRANSACTION_MAJ_CONFIGURATION_USAGER => commande_maj_configuration_usager(middleware, m, gestionnaire).await,
        TRANSACTION_MAJ_SENSEUR |
        TRANSACTION_MAJ_NOEUD |
        TRANSACTION_SUPPRESSION_SENSEUR |
        TRANSACTION_MAJ_APPAREIL => {
            // Pour l'instant, aucune autre validation. On traite comme une transaction
            Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
        }
        TRANSACTION_APPAREIL_SUPPRIMER |
        TRANSACTION_APPAREIL_RESTAURER |
        TRANSACTION_SAUVEGARDER_PROGRAMME => {
            if user_id.is_none() {
                Err(format!("senseurspassifs.consommer_commande: Commande autorisation invalide (user_id requis) pour message {:?}", m.correlation_id))?
            }
            // Pour l'instant, aucune autre validation. On traite comme une transaction
            Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
        }
        _ => Err(format!("senseurspassifs.consommer_commande: Commande {} inconnue : {}, message dropped", DOMAINE_NOM, m.action))?,
    }
}

async fn commande_inscrire_appareil<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireSenseursPassifs)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
{
    debug!("commande_inscrire_appareil Consommer requete : {:?}", & m.message);
    let mut commande: CommandeInscrireAppareil = m.message.get_msg().map_contenu()?;
    debug!("commande_inscrire_appareil Commande mappee : {:?}", commande);

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
        collection.find_one_and_update(filtre_appareil.clone(), ops, Some(options)).await?
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

                    // debug!("commande_inscrire_appareil Reset certificat, demande avec nouveau CSR");
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
                return Ok(Some(middleware.formatter_reponse(reponse, None)?));
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
    collection.update_one(filtre_appareil.clone(), ops, None).await?;

    let reponse = json!({"ok": true});
    return Ok(Some(middleware.formatter_reponse(reponse, None)?));
}

async fn commande_signer_appareil<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireSenseursPassifs)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + ValidateurX509 + MongoDao + VerificateurMessage,
{
    debug!("commande_signer_appareil Consommer requete : {:?}", & m.message);
    let mut commande: CommandeSignerAppareil = m.message.get_msg().map_contenu()?;
    debug!("commande_signer_appareil Commande mappee : {:?}", commande);

    let user_id = match m.get_user_id() {
        Some(inner) => inner,
        None => {
            let reponse = json!({"ok": false, "err": "user_id manquant"});
            return Ok(Some(middleware.formatter_reponse(&reponse, None)?));
        }
    };

    let collection = middleware.get_collection(COLLECTIONS_APPAREILS)?;

    let mut renouvellement = false;
    if let Some(csr) = commande.csr.as_ref() {
        if let Some(certificat) = m.message.certificat.as_ref() {
            if let Some(cn) = certificat.subject()?.get("commonName") {
                if commande.uuid_appareil.as_str() == cn.as_str() {
                    debug!("Renouvellement d'un certificat d'appareil valide pour {}", cn);
                    renouvellement = true;
                }
            }
        }
    }

    let filtre_appareil = doc! {
        "uuid_appareil": &commande.uuid_appareil,
        "user_id": &user_id,
    };

    let mut doc_appareil = {
        let d = collection.find_one(filtre_appareil.clone(), None).await?;
        match d {
            Some(d) => {
                let doc_appareil: DocAppareil = convertir_bson_deserializable(d)?;
                doc_appareil
            },
            None => {
                let reponse = json!({"ok": false, "err": "appareil inconnu"});
                return Ok(Some(middleware.formatter_reponse(&reponse, None)?));
            }
        }
    };

    let certificat = match renouvellement {
        true => signer_certificat(middleware, user_id.as_str(), filtre_appareil, doc_appareil.clone(), commande.csr.as_ref()).await?,
        false => match doc_appareil.certificat {
            Some(c) => c,
            None => {
                signer_certificat(middleware, user_id.as_str(), filtre_appareil, doc_appareil.clone(), None).await?
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
        sauvegarder_traiter_transaction_serializable(
            middleware, &transaction, gestionnaire,
            DOMAINE_NOM, TRANSACTION_INIT_APPAREIL).await?;
    }

    debug!("Repondre avec certificat");
    let reponse = json!({
        "ok": true,
        "certificat": certificat,
    });

    Ok(Some(middleware.formatter_reponse(reponse, None)?))
}

async fn commande_maj_configuration_usager<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireSenseursPassifs)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + ValidateurX509 + MongoDao + VerificateurMessage,
{
    debug!("commande_maj_configuration_usager Consommer requete : {:?}", & m.message);
    let mut commande: TransactionMajConfigurationUsager = m.message.get_msg().map_contenu()?;

    let user_id = match m.get_user_id() {
        Some(inner) => inner,
        None => {
            let reponse = json!({"ok": false, "err": "user_id manquant"});
            return Ok(Some(middleware.formatter_reponse(&reponse, None)?));
        }
    };

    Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
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

async fn commande_challenge_appareil<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireSenseursPassifs)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
{
    debug!("commande_challenge_appareil Consommer requete : {:?}", & m.message);
    let mut commande: CommandeChallengeAppareil = m.message.get_msg().map_contenu()?;
    debug!("commande_challenge_appareil Commande mappee : {:?}", commande);

    let user_id = match m.get_user_id() {
        Some(inner) => inner,
        None => {
            let reponse = json!({"ok": false, "err": "user_id manquant"});
            return Ok(Some(middleware.formatter_reponse(&reponse, None)?));
        }
    };

    let collection = middleware.get_collection(COLLECTIONS_APPAREILS)?;

    let doc_appareil_option = {
        let filtre = doc! {"uuid_appareil": &commande.uuid_appareil, "user_id": user_id};
        collection.find_one(filtre, None).await?
    };

    let doc_appareil: DocAppareil = match doc_appareil_option {
        Some(d) => convertir_bson_deserializable(d)?,
        None => {
            let reponse = json!({"ok": false, "err": "Appareil inconnu"});
            return Ok(Some(middleware.formatter_reponse(&reponse, None)?));
        }
    };

    let instance_id = match doc_appareil.instance_id {
        Some(inner) => inner,
        None => {
            let reponse = json!({"ok": false, "err": "Pas d'instance_id pour cet appareil"});
            return Ok(Some(middleware.formatter_reponse(reponse, None)?))
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
    let routage = RoutageMessageAction::builder("senseurspassifs_relai", "challengeAppareil")
        .partition(instance_id)
        .exchanges(vec![Securite::L2Prive])
        .build();
    middleware.transmettre_commande(routage, &message_challenge, false).await?;

    return Ok(middleware.reponse_ok()?)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CommandeChallengeAppareil {
    uuid_appareil: String,
    challenge: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CommandeConfirmerRelai {
    fingerprint: String,
    expiration: Option<DateEpochSeconds>,
}

#[derive(Deserialize)]
pub struct RowRelais {
    pub fingerprint: String,
    pub user_id: String,
    pub expiration: Option<DateEpochSeconds>,
}

async fn commande_confirmer_relai<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireSenseursPassifs)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
{
    debug ! ("commande_confirmer_relai Consommer requete : {:?}", & m.message);
    let mut commande: CommandeConfirmerRelai = m.message.get_msg().map_contenu() ?;
    debug ! ("commande_confirmer_relai Commande mappee : {:?}", commande);

    let certificat = match m.message.certificat {
        Some(inner) => inner,
        None => Err(format!("commande_confirmer_relai Certificat manquant du message"))?
    };
    let common_name = certificat.get_common_name()?;
    let user_id = match certificat.get_user_id()? {
        Some(inner) => inner.as_str(),
        None => Err(format!("commande_confirmer_relai Certificat sans user_id"))?
    };

    let filtre = doc! { "uuid_appareil": &common_name, "user_id": user_id };
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
    collection.update_one(filtre, ops, options).await?;

    Ok(middleware.reponse_ok()?)
}

async fn signer_certificat<M>(middleware: &M, user_id: &str, filtre_appareil: Document, doc_appareil: DocAppareil, csr_inclus: Option<&String>)
    -> Result<Vec<String>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage
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
    let routage = RoutageMessageAction::builder("CorePki", "signerCsr")
        .exchanges(vec![Securite::L3Protege])
        .build();
    let requete = json!({
        "csr": csr,  // &doc_appareil.csr,
        "roles": ["senseurspassifs"],
        "user_id": user_id,
    });

    debug!("signer_certificat Requete demande signer appareil : {:?}", requete);
    let reponse: ReponseCertificat = match middleware.transmettre_commande(routage, &requete, true).await? {
        Some(r) => match r {
            TypeMessage::Valide(m) => m.message.parsed.map_contenu()?,
            _ => {
                Err(format!("senseurspassifs.signer_certificat Reponse certissuer invalide"))?
            }
        },
        None => {
            Err(format!("senseurspassifs.signer_certificat Aucune reponse"))?
        }
    };

    debug!("signer_certificat Reponse : {:?}", reponse);
    if let Some(true) = reponse.ok {
        let (certificat, fingerprint) = match &reponse.certificat {
            Some(c) => {
                let cert_x509 = charger_certificat(c[0].as_str());
                (c.to_owned(), calculer_fingerprint(&cert_x509)?)
            },
            None => {
                Err(format!("senseurspassifs.signer_certificat Reponse serveur incorrect (cert)"))?
            }
        };

        let ops = doc! {
            "$set": {
                "certificat": &reponse.certificat,
                "fingerprint": fingerprint,
            },
            "$unset": {"csr": true},
            "$currentDate": {CHAMP_MODIFICATION: true},
        };

        let collection = middleware.get_collection(COLLECTIONS_APPAREILS)?;
        collection.update_one(filtre_appareil, ops, None).await?;

        Ok(certificat)  // Retourner certificat via reponse
    } else {
        Err(format!("senseurspassifs.signer_certificat Reponse serveur incorrect (ok=false)"))?
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

async fn commande_reset_certificats<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireSenseursPassifs)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
{
    debug ! ("commande_reset_certificats Consommer requete : {:?}", & m.message);

    if ! (m.verifier_roles(vec![RolesCertificats::ComptePrive]) || m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)){
        let reponse = middleware.formatter_reponse(ReponseCommandeResetCertificat{ok: false, err: Some("Acces refuse".to_string())}, None)?;
        return Ok(Some(reponse))
    }

    let certificat = match m.message.certificat {
        Some(inner) => inner,
        None => Err(format!("commande_reset_certificats Certificat manquant du message"))?
    };

    let user_id = match certificat.get_user_id()? {
        Some(inner) => inner.as_str(),
        None => Err("commande_reset_certificats Certificat sans user_id".to_string())?
    };

    let filtre = doc!{ CHAMP_USER_ID: user_id };
    let collection = middleware.get_collection(COLLECTIONS_APPAREILS)?;
    let ops = doc! {
        "$unset": {TRANSACTION_CHAMP_CERTIFICAT: true, PKI_DOCUMENT_CHAMP_FINGERPRINT: true},
        "$currentDate": {CHAMP_MODIFICATION: true}
    };
    collection.update_many(filtre, ops, None).await?;

    let reponse = middleware.formatter_reponse(ReponseCommandeResetCertificat{ok: true, err: None}, None)?;
    Ok(Some(reponse))
}
