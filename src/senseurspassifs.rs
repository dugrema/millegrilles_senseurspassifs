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
use millegrilles_common_rust::middleware::{EmetteurNotificationsTrait, Middleware, sauvegarder_traiter_transaction, sauvegarder_traiter_transaction_serializable};
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
use crate::commandes::consommer_commande;

use crate::requetes::consommer_requete;
use crate::common::*;
use crate::evenements::evenement_appareil_presence;
use crate::lectures::{detecter_presence_appareils, evenement_domaine_lecture, generer_transactions_lectures_horaires};
use crate::transactions::{aiguillage_transaction, TransactionInitialiserAppareil, TransactionMajAppareil};

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
        COLLECTIONS_RELAIS.to_string(),
        COLLECTIONS_USAGER.to_string(),
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
        REQUETE_GET_CONFIGURATION_USAGER,
        REQUETE_GET_TIMEZONE_APPAREIL,
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
    rk_volatils.push(ConfigRoutingExchange { routing_key: format!("evenement.{}.{}", ROLE_RELAI_NOM, EVENEMENT_PRESENCE_APPAREIL), exchange: Securite::L2Prive });

    let commandes_transactions: Vec<&str> = vec![
        // Transactions usager, verifier via commande
        TRANSACTION_LECTURE,
        TRANSACTION_MAJ_SENSEUR,
        TRANSACTION_MAJ_NOEUD,
        TRANSACTION_SUPPRESSION_SENSEUR,
        TRANSACTION_MAJ_APPAREIL,
        TRANSACTION_SAUVEGARDER_PROGRAMME,
        TRANSACTION_APPAREIL_SUPPRIMER,
        TRANSACTION_APPAREIL_RESTAURER,
        TRANSACTION_MAJ_CONFIGURATION_USAGER,
        COMMANDE_INSCRIRE_APPAREIL,
        COMMANDE_CHALLENGE_APPAREIL,
        COMMANDE_SIGNER_APPAREIL,
        COMMANDE_CONFIRMER_RELAI,
        COMMANDE_RESET_CERTIFICATS,
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
        TRANSACTION_INIT_APPAREIL,
        TRANSACTION_APPAREIL_SUPPRIMER,
        TRANSACTION_APPAREIL_RESTAURER,
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

    // Appareils date_lecture/present
    let options_appareils_derniere_lecture = IndexOptions {
        nom_index: Some(String::from(INDEX_APPAREILS_DERNIERE_LECTURE)),
        unique: false
    };
    let champs_appareils_deniere_lecture = vec!(
        ChampIndex {nom_champ: String::from(CHAMP_DERNIERE_LECTURE), direction: 1},
        ChampIndex {nom_champ: String::from(CHAMP_PRESENT), direction: 1},
    );
    middleware.create_index(
        middleware,
        COLLECTIONS_APPAREILS,
        champs_appareils_deniere_lecture,
        Some(options_appareils_derniere_lecture)
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

    // Notifications usager
    let options_notifications_usager = IndexOptions {
        nom_index: Some(String::from(INDEX_USER_NOTIFICATIONS)),
        unique: true
    };
    let champs_index_notifications_usager = vec!(
        ChampIndex {nom_champ: String::from(CHAMP_USER_ID), direction: 1},
    );
    middleware.create_index(
        middleware,
        COLLECTIONS_NOTIFICATIONS_USAGERS,
        champs_index_notifications_usager,
        Some(options_notifications_usager)
    ).await?;

    // Notifications usager
    let options_relais = IndexOptions {
        nom_index: Some(String::from(INDEX_USER_APPAREIL_RELAIS)),
        unique: true
    };
    let champs_index_relais = vec!(
        ChampIndex {nom_champ: String::from(CHAMP_UUID_APPAREIL), direction: 1},
        ChampIndex {nom_champ: String::from(CHAMP_USER_ID), direction: 1},
    );
    middleware.create_index(
        middleware,
        COLLECTIONS_RELAIS,
        champs_index_relais,
        Some(options_relais)
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

    // Faire l'aggretation des lectures
    // Va chercher toutes les lectures non traitees de l'heure precedente (-65 minutes)
    if let Err(e) = generer_transactions_lectures_horaires(middleware).await {
        error!("traiter_cedule Erreur generer_transactions : {:?}", e);
    }

    if minute % 2 == 0 {
        if let Err(e) = detecter_presence_appareils(middleware).await {
            error!("traiter_cedule Detecter appareils presents/absents : {:?}", e);
        }
    }


    Ok(())
}

async fn consommer_evenement<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireSenseursPassifs) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
where
    M: ValidateurX509 + VerificateurMessage + GenerateurMessages + MongoDao + EmetteurNotificationsTrait
{
    debug!("senseurspassifs.consommer_evenement Consommer evenement : {:?}", &m.message);

    // Autorisation : doit etre de niveau 2.prive, 3.protege ou 4.secure
    match m.verifier_exchanges(vec![Securite::L2Prive, Securite::L3Protege, Securite::L4Secure]) {
        true => Ok(()),
        false => Err(format!("senseurspassifs.consommer_evenement: Evenement invalide (pas 2.prive, 3.protege ou 4.secure)")),
    }?;

    match m.action.as_str() {
        EVENEMENT_LECTURE => { evenement_domaine_lecture(middleware, &m, gestionnaire).await?; Ok(None) },
        EVENEMENT_PRESENCE_APPAREIL => { evenement_appareil_presence(middleware, &m, gestionnaire).await?; Ok(None) },
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
        TRANSACTION_SENSEUR_HORAIRE |
        TRANSACTION_APPAREIL_SUPPRIMER |
        TRANSACTION_APPAREIL_RESTAURER => {
            Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
        },
        _ => Err(format!("senseurspassifs.consommer_transaction: Mauvais type d'action pour une transaction : {}", m.action))?,
    }
}
