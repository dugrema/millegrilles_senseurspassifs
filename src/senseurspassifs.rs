use std::collections::{BTreeMap, HashMap, HashSet};
use std::error::Error;
use std::sync::Arc;

use log::{debug, error, warn};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::bson::{DateTime, doc, Document};
use millegrilles_common_rust::certificats::{calculer_fingerprint, charger_certificat, ValidateurX509, VerificateurPermissions};
// use millegrilles_common_rust::chiffrage_cle::CommandeSauvegarderCle;
use millegrilles_common_rust::{chrono, chrono::Utc};
use millegrilles_common_rust::chrono::Timelike;
use millegrilles_common_rust::configuration::ConfigMessages;
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::domaines::GestionnaireDomaine;
use millegrilles_common_rust::formatteur_messages::{DateEpochSeconds, MessageMilleGrille, MessageSerialise};
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::hachages::hacher_uuid;
use millegrilles_common_rust::messages_generiques::MessageCedule;
use millegrilles_common_rust::middleware::{Middleware, sauvegarder_traiter_transaction};
use millegrilles_common_rust::mongodb::options::{CountOptions, FindOneAndUpdateOptions, FindOneOptions, FindOptions, Hint, ReturnDocument, UpdateOptions};
use millegrilles_common_rust::rabbitmq_dao::{ConfigQueue, ConfigRoutingExchange, QueueType};
use millegrilles_common_rust::recepteur_messages::{MessageValideAction, TypeMessage};
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::serde_json::{json, Value};
use millegrilles_common_rust::tokio::time::{Duration, sleep};
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::transactions::{TraiterTransaction, Transaction, TransactionImpl};
use millegrilles_common_rust::verificateur::VerificateurMessage;
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, ChampIndex, IndexOptions, MongoDao, convertir_to_bson, convertir_bson_value, filtrer_doc_id, convertir_to_bson_array};
use millegrilles_common_rust::mongodb::Collection;

use crate::requetes::consommer_requete;
use crate::common::*;
use crate::lectures::{evenement_domaine_lecture, generer_transactions_lectures_horaires};
use crate::transactions::aiguillage_transaction;

const INDEX_LECTURES_NOEUD: &str = "lectures_noeud";
const INDEX_LECTURES_SENSEURS: &str = "lectures_senseur";
const INDEX_LECTURES_HORAIRE: &str = "lectures_horaire";
const INDEX_LECTURES_HORAIRE_RAPPORT: &str = "lectures_horaire_rapport";
const INDEX_USER_APPAREILS: &str = "user_appareils";

#[derive(Clone, Debug)]
pub struct GestionnaireSenseursPassifs {
    pub instance_id: String,
}

#[async_trait]
impl TraiterTransaction for GestionnaireSenseursPassifs {
    async fn appliquer_transaction<M>(&self, middleware: &M, transaction: TransactionImpl) -> Result<Option<MessageMilleGrille>, String>
        where M: ValidateurX509 + GenerateurMessages + MongoDao
    {
        aiguillage_transaction(middleware, transaction, &self).await
    }
}

#[async_trait]
impl GestionnaireDomaine for GestionnaireSenseursPassifs {
    fn get_nom_domaine(&self) -> String { String::from(DOMAINE_NOM) }

    fn get_collection_transactions(&self) -> Option<String> {
        Some(COLLECTIONS_NOM.to_string())
    }

    fn get_collections_documents(&self) -> Vec<String> { vec![
        COLLECTIONS_INSTANCES.to_string(),
        COLLECTIONS_LECTURES.to_string(),
        COLLECTIONS_APPAREILS.to_string(),
        COLLECTIONS_SENSEURS_HORAIRE.to_string(),
    ] }

    fn get_q_transactions(&self) -> Option<String> {
        Some(format!("{}/transactions", DOMAINE_NOM))
    }

    fn get_q_volatils(&self) -> Option<String> {
        Some(format!("{}/volatils", DOMAINE_NOM))
    }

    fn get_q_triggers(&self) -> Option<String> {
        Some(format!("{}/triggers", DOMAINE_NOM))
    }

    fn preparer_queues(&self) -> Vec<QueueType> { preparer_queues(self) }

    fn chiffrer_backup(&self) -> bool {
        true
    }

    async fn preparer_database<M>(&self, middleware: &M) -> Result<(), String> where M: MongoDao + ConfigMessages {
        preparer_index_mongodb_custom(middleware, &self).await
    }

    async fn consommer_requete<M>(&self, middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>> where M: Middleware + 'static {
        consommer_requete(middleware, message, &self).await
    }

    async fn consommer_commande<M>(&self, middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>> where M: Middleware + 'static {
        consommer_commande(middleware, message, &self).await
    }

    async fn consommer_transaction<M>(&self, middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>> where M: Middleware + 'static {
        consommer_transaction(middleware, message, self).await
    }

    async fn consommer_evenement<M>(self: &'static Self, middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>> where M: Middleware + 'static {
        consommer_evenement(middleware, message, self).await
    }

    async fn entretien<M>(self: &'static Self, middleware: Arc<M>) where M: Middleware + 'static {
        entretien(middleware).await
    }

    async fn traiter_cedule<M>(self: &'static Self, middleware: &M, trigger: &MessageCedule) -> Result<(), Box<dyn Error>> where M: Middleware + 'static {
        traiter_cedule(middleware, trigger).await
    }

    async fn aiguillage_transaction<M, T>(&self, middleware: &M, transaction: T) -> Result<Option<MessageMilleGrille>, String> where M: ValidateurX509 + GenerateurMessages + MongoDao, T: Transaction {
        aiguillage_transaction(middleware, transaction, &self).await
    }
}

pub fn preparer_queues(gestionnaire: &GestionnaireSenseursPassifs) -> Vec<QueueType> {
    let mut rk_volatils = Vec::new();

    // RK 2.prive, 3.protege et 4.secure
    let requetes_privees: Vec<&str> = vec![
        REQUETE_GET_APPAREILS_USAGER,
        REQUETE_GET_APPAREIL_DISPLAY_CONFIGURATION,
        REQUETE_GET_APPAREIL_PROGRAMMES_CONFIGURATION,
        REQUETE_LISTE_NOEUDS,
        REQUETE_GET_NOEUD,
        REQUETE_LISTE_SENSEURS_PAR_UUID,
        REQUETE_LISTE_SENSEURS_NOEUD,
        REQUETE_GET_APPAREILS_EN_ATTENTE,
        REQUETE_GET_STATISTIQUES_SENSEUR,
    ];
    for req in requetes_privees {
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("requete.{}.{}", DOMAINE_NOM, req), exchange: Securite::L2Prive});
    }

    // Requete liste noeuds permet de trouver les noeuds sur toutes les partitions (potentiellement plusieurs reponses)
    rk_volatils.push(ConfigRoutingExchange {routing_key: format!("requete.{}.{}", DOMAINE_NOM, REQUETE_GET_NOEUD), exchange: Securite::L2Prive});
    rk_volatils.push(ConfigRoutingExchange {routing_key: format!("requete.{}.{}", DOMAINE_NOM, REQUETE_LISTE_NOEUDS), exchange: Securite::L2Prive});

    let evenements: Vec<&str> = vec![
        EVENEMENT_LECTURE,
    ];
    for evnt in evenements {
        rk_volatils.push(ConfigRoutingExchange { routing_key: format!("evenement.{}.{}", DOMAINE_NOM, evnt), exchange: Securite::L2Prive });
        rk_volatils.push(ConfigRoutingExchange { routing_key: format!("evenement.{}.{}", ROLE_RELAI_NOM, evnt), exchange: Securite::L2Prive });
    }

    let commandes_transactions: Vec<&str> = vec![
        // Transactions usager, verifier via commande
        TRANSACTION_LECTURE,
        TRANSACTION_MAJ_SENSEUR,
        TRANSACTION_MAJ_NOEUD,
        TRANSACTION_SUPPRESSION_SENSEUR,
        TRANSACTION_MAJ_APPAREIL,
        COMMANDE_INSCRIRE_APPAREIL,
        COMMANDE_CHALLENGE_APPAREIL,
        COMMANDE_SIGNER_APPAREIL,
    ];
    for cmd in commandes_transactions {
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("commande.{}.{}", DOMAINE_NOM, cmd), exchange: Securite::L2Prive});
    }

    rk_volatils.push(ConfigRoutingExchange {
        routing_key: format!("commande.{}.{}.{}", DOMAINE_NOM, gestionnaire.instance_id.as_str(), TRANSACTION_LECTURE).into(),
        exchange: Securite::L2Prive
    });

    let mut queues = Vec::new();

    // Queue de messages volatils (requete, commande, evenements)
    queues.push(QueueType::ExchangeQueue (
        ConfigQueue {
            nom_queue: gestionnaire.get_q_volatils().expect("get_q_volatils").into(),
            routing_keys: rk_volatils,
            ttl: DEFAULT_Q_TTL.into(),
            durable: false,
            autodelete: false,
        }
    ));

    let mut rk_transactions = Vec::new();

    let transactions_sec = vec![
        TRANSACTION_LECTURE,
        TRANSACTION_MAJ_SENSEUR,
        TRANSACTION_MAJ_NOEUD,
        TRANSACTION_SUPPRESSION_SENSEUR,
        TRANSACTION_MAJ_APPAREIL,
        TRANSACTION_SENSEUR_HORAIRE,
    ];
    for trans in &transactions_sec {
        rk_transactions.push(ConfigRoutingExchange {
            routing_key: format!("transaction.{}.{}", DOMAINE_NOM, trans).into(),
            exchange: Securite::L4Secure,
        });
    }

    // Queue de transactions
    queues.push(QueueType::ExchangeQueue (
        ConfigQueue {
            nom_queue: gestionnaire.get_q_transactions().expect("get_q_transactions").into(),
            routing_keys: rk_transactions,
            ttl: None,
            durable: false,
            autodelete: false,
        }
    ));

    // Queue de triggers
    queues.push(QueueType::Triggers (format!("{}", DOMAINE_NOM), Securite::L3Protege));

    queues
}

/// Creer index MongoDB
pub async fn preparer_index_mongodb_custom<M>(middleware: &M, gestionnaire: &GestionnaireSenseursPassifs) -> Result<(), String>
    where M: MongoDao + ConfigMessages
{
    // Index senseurs
    // let options_lectures_noeud = IndexOptions {
    //     nom_index: Some(String::from(INDEX_LECTURES_NOEUD)),
    //     unique: false
    // };
    // let champs_index_lectures_noeud = vec!(
    //     ChampIndex {nom_champ: String::from(CHAMP_INSTANCE_ID), direction: 1},
    // );
    // middleware.create_index(
    //     middleware,
    //     COLLECTIONS_LECTURES,
    //     champs_index_lectures_noeud,
    //     Some(options_lectures_noeud)
    // ).await?;

    let options_appareils = IndexOptions {
        nom_index: Some(String::from(INDEX_USER_APPAREILS)),
        unique: true
    };
    let champs_index_appareils = vec!(
        ChampIndex {nom_champ: String::from(CHAMP_USER_ID), direction: 1},
        ChampIndex {nom_champ: String::from(CHAMP_UUID_APPAREIL), direction: 1},
    );
    middleware.create_index(
        middleware,
        COLLECTIONS_APPAREILS,
        champs_index_appareils,
        Some(options_appareils)
    ).await?;

    let options_lectures_senseurs = IndexOptions {
        nom_index: Some(String::from(INDEX_LECTURES_SENSEURS)),
        unique: true
    };
    let champs_index_lectures_senseurs = vec!(
        ChampIndex {nom_champ: String::from(CHAMP_USER_ID), direction: 1},
        ChampIndex {nom_champ: String::from(CHAMP_UUID_APPAREIL), direction: 1},
        ChampIndex {nom_champ: String::from("senseur_id"), direction: 1},
        ChampIndex {nom_champ: String::from("heure"), direction: 1},
    );
    middleware.create_index(
        middleware,
        COLLECTIONS_LECTURES,
        champs_index_lectures_senseurs,
        Some(options_lectures_senseurs)
    ).await?;

    // // Index noeuds
    // let options_lectures_noeud = IndexOptions {
    //     nom_index: Some(String::from(INDEX_LECTURES_NOEUD)),
    //     unique: true
    // };
    // let champs_index_lectures_noeud = vec!(
    //     ChampIndex {nom_champ: String::from(CHAMP_INSTANCE_ID), direction: 1},
    // );
    // middleware.create_index(
    //     middleware,
    //     COLLECTIONS_INSTANCES,
    //     champs_index_lectures_noeud,
    //     Some(options_lectures_noeud)
    // ).await?;

    // Lectures horaire
    let options_senseurs_horaires = IndexOptions {
        nom_index: Some(String::from(INDEX_LECTURES_HORAIRE)),
        unique: true
    };
    let champs_index_senseurs_horaire = vec!(
        ChampIndex {nom_champ: String::from(CHAMP_USER_ID), direction: 1},
        ChampIndex {nom_champ: String::from(CHAMP_UUID_APPAREIL), direction: 1},
        ChampIndex {nom_champ: String::from("senseur_id"), direction: 1},
        ChampIndex {nom_champ: String::from("heure"), direction: 1},
    );
    middleware.create_index(
        middleware,
        COLLECTIONS_SENSEURS_HORAIRE,
        champs_index_senseurs_horaire,
        Some(options_senseurs_horaires)
    ).await?;

    // Lectures horaire
    let options_senseurs_horaires_rapport = IndexOptions {
        nom_index: Some(String::from(INDEX_LECTURES_HORAIRE_RAPPORT)),
        unique: false
    };
    let champs_index_senseurs_horaire_rapport = vec!(
        ChampIndex {nom_champ: String::from("heure"), direction: 1},
    );
    middleware.create_index(
        middleware,
        COLLECTIONS_LECTURES,
        champs_index_senseurs_horaire_rapport,
        Some(options_senseurs_horaires_rapport)
    ).await?;

    Ok(())
}

pub async fn entretien<M>(_middleware: Arc<M>)
    where M: Middleware + 'static
{
    loop {
        sleep(Duration::new(30, 0)).await;
        debug!("Cycle entretien {}", DOMAINE_NOM);
    }
}

pub async fn traiter_cedule<M>(middleware: &M, trigger: &MessageCedule) -> Result<(), Box<dyn Error>>
where M: Middleware + 'static {
    // let message = trigger.message;

    debug!("Traiter cedule {}", DOMAINE_NOM);

    if middleware.get_mode_regeneration() == true {
        debug!("traiter_cedule Mode regeneration actif, abort entretien");
        return Ok(())
    }

    let minute = trigger.get_date().get_datetime().minute();

    // if minute % 5 == 4 {
        // Faire l'aggretation des lectures toutes les 5 minutes (offset 4 minutes apres l'heure)
        if let Err(e) = generer_transactions_lectures_horaires(middleware).await {
            error!("traiter_cedule Erreur generer_transactions : {:?}", e);
        }
    //}

    Ok(())
}

async fn consommer_evenement<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireSenseursPassifs) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
where
    M: ValidateurX509 + VerificateurMessage + GenerateurMessages + MongoDao,
{
    debug!("senseurspassifs.consommer_evenement Consommer evenement : {:?}", &m.message);

    // Autorisation : doit etre de niveau 2.prive, 3.protege ou 4.secure
    match m.verifier_exchanges(vec![Securite::L2Prive, Securite::L3Protege, Securite::L4Secure]) {
        true => Ok(()),
        false => Err(format!("senseurspassifs.consommer_evenement: Evenement invalide (pas 2.prive, 3.protege ou 4.secure)")),
    }?;

    match m.action.as_str() {
        EVENEMENT_LECTURE => { evenement_domaine_lecture(middleware, &m, gestionnaire).await?; Ok(None) },
        _ => Err(format!("senseurspassifs.consommer_evenement: Mauvais type d'action pour une transaction : {}", m.action))?,
    }
}

async fn consommer_transaction<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireSenseursPassifs) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao + VerificateurMessage
{
    debug!("senseurspassifs.consommer_transaction Consommer transaction : {:?}", &m.message);

    // Autorisation : doit etre de niveau 2.prive, 3.protege ou 4.secure
    match m.verifier_exchanges(vec![Securite::L2Prive, Securite::L3Protege, Securite::L4Secure]) {
        true => Ok(()),
        false => {
            match m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
                true => Ok(()),
                false => Err(format!("senseurspassifs.consommer_transaction: Trigger cedule autorisation invalide (pas 4.secure ou proprietaire)"))
            }
        },
    }?;

    match m.action.as_str() {
        TRANSACTION_MAJ_SENSEUR |
        TRANSACTION_MAJ_NOEUD |
        TRANSACTION_LECTURE |
        TRANSACTION_SUPPRESSION_SENSEUR |
        TRANSACTION_MAJ_APPAREIL |
        TRANSACTION_SENSEUR_HORAIRE => {
            Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
        },
        _ => Err(format!("senseurspassifs.consommer_transaction: Mauvais type d'action pour une transaction : {}", m.action))?,
    }
}

async fn consommer_commande<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireSenseursPassifs)
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
        TRANSACTION_MAJ_SENSEUR |
        TRANSACTION_MAJ_NOEUD |
        TRANSACTION_SUPPRESSION_SENSEUR |
        TRANSACTION_MAJ_APPAREIL => {
            // Pour l'instant, aucune autre validation. On traite comme une transaction
            Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
        },
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
        let set_on_insert = doc! {
            CHAMP_CREATION: Utc::now(),
            CHAMP_MODIFICATION: Utc::now(),
            "uuid_appareil": &commande.uuid_appareil,
            "cle_publique": &commande.cle_publique,
            "csr": &commande.csr,
            "instance_id": &commande.instance_id,
            "user_id": &commande.user_id,
        };
        let options = FindOneAndUpdateOptions::builder()
            .upsert(true)
            .return_document(ReturnDocument::After)
            .build();
        let ops = doc! { "$setOnInsert": set_on_insert };
        collection.find_one_and_update(filtre_appareil.clone(), ops, Some(options)).await?
    };

    if let Some(d) = doc_appareil_option {
        let doc_appareil: DocAppareil = convertir_bson_deserializable(d)?;
        let mut certificat = doc_appareil.certificat;


        match certificat {
            Some(c) => {
                let mut repondre_certificat = false;

                // Comparer cles publiques - si differentes, on genere un nouveau certificat
                if let Some(cle_publique_db) = doc_appareil.cle_publique.as_ref() {
                    if &commande.cle_publique != cle_publique_db {
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
                // Rien a faire, on a conserve le certificat
            }
        }

    } else {
        error!("commande_inscrire_appareil Erreur db - document pas insere");
    }

    let reponse = json!({"ok": true});
    return Ok(Some(middleware.formatter_reponse(reponse, None)?));
}

async fn commande_signer_appareil<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireSenseursPassifs)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
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
        true => signer_certificat(middleware, user_id.as_str(), filtre_appareil, doc_appareil, commande.csr.as_ref()).await?,
        false => match doc_appareil.certificat {
            Some(c) => c,
            None => {
                signer_certificat(middleware, user_id.as_str(), filtre_appareil, doc_appareil, None).await?
            }
        }
    };

    debug!("Repondre avec certificat");
    let reponse = json!({
        "ok": true,
        "certificat": certificat,
    });

    Ok(Some(middleware.formatter_reponse(reponse, None)?))
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

    // Emettre la commande de challenge
    let message_challenge = json!({
        "ok": true,
        "uuid_appareil": &commande.uuid_appareil,
        "challenge": &commande.challenge,
        "cle_publique": doc_appareil.cle_publique,
        "fingerprint": doc_appareil.fingerprint,
    });
    let routage = RoutageMessageAction::builder("senseurspassifs_relai", "challengeAppareil")
        .partition(doc_appareil.instance_id)
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
