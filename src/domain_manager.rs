use log::{debug, error};
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::backup::BackupStarter;
use millegrilles_common_rust::certificats::ValidateurX509;
use millegrilles_common_rust::chrono::Timelike;
use millegrilles_common_rust::configuration::ConfigMessages;
use millegrilles_common_rust::constantes::{Securite, DEFAULT_Q_TTL};
use millegrilles_common_rust::db_structs::TransactionValide;
use millegrilles_common_rust::domaines_traits::{AiguillageTransactions, ConsommateurMessagesBus, GestionnaireBusMillegrilles, GestionnaireDomaineV2};
use millegrilles_common_rust::domaines_v2::{prepare_mongodb_domain_indexes, GestionnaireDomaineSimple};
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::mongo_dao::{start_transaction_regular, MongoDao};
use millegrilles_common_rust::messages_generiques::MessageCedule;
use millegrilles_common_rust::middleware::{Middleware, MiddlewareMessages};
use millegrilles_common_rust::mongodb::ClientSession;
use millegrilles_common_rust::rabbitmq_dao::{ConfigQueue, ConfigRoutingExchange, QueueType};
use millegrilles_common_rust::recepteur_messages::MessageValide;
use crate::builder::preparer_index_mongodb;
use crate::commandes::consommer_commande;
use crate::requetes::consommer_requete;
use crate::common::*;
use crate::constants::*;
use crate::evenements::consommer_evenement;
use crate::lectures::{generer_transactions_lectures_horaires, rebuild_sensor_list};
use crate::maintenance::{maintain_device_certificates, mark_devices_offline};
use crate::transactions::aiguillage_transaction;

#[derive(Clone)]
pub struct SenseursPassifsDomainManager {
    pub instance_id: String,
}

impl SenseursPassifsDomainManager {
    pub fn new(instance_id: String) -> SenseursPassifsDomainManager {
        SenseursPassifsDomainManager { instance_id }
    }
}

impl GestionnaireDomaineV2 for SenseursPassifsDomainManager {
    fn get_collection_transactions(&self) -> Option<String> {
        Some(String::from(COLLECTION_NAME_TRANSACTIONS))
    }

    fn get_collections_volatiles(&self) -> Result<Vec<String>, CommonError> {
        Ok(vec![
            COLLECTIONS_INSTANCES.to_string(),
            COLLECTIONS_APPAREILS.to_string(),
            COLLECTIONS_SENSEURS_HORAIRE.to_string(),
            COLLECTIONS_USAGER.to_string(),

            // Ignorer les collections lectures et relais pour regeneration
            // Elles ne sont pas conservees dans des transactions (purement volatiles)
            // COLLECTIONS_LECTURES.to_string(),
            // COLLECTIONS_RELAIS.to_string(),
        ])
    }

    fn get_rebuild_transaction_batch_size(&self) -> u64 { 500 }
}

impl GestionnaireBusMillegrilles for SenseursPassifsDomainManager {
    fn get_nom_domaine(&self) -> String {
        DOMAIN_NAME.to_string()
    }

    fn get_q_volatils(&self) -> String {
        format!("{}/volatiles", DOMAIN_NAME)
    }

    fn get_q_triggers(&self) -> String {
        format!("{}/triggers", DOMAIN_NAME)
    }

    fn preparer_queues(&self) -> Vec<QueueType> {
        preparer_queues(self)
    }
}

#[async_trait]
impl ConsommateurMessagesBus for SenseursPassifsDomainManager {
    async fn consommer_requete<M>(&self, middleware: &M, message: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where
        M: Middleware
    {
        consommer_requete(middleware, message, self).await
    }

    async fn consommer_commande<M>(&self, middleware: &M, message: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where
        M: Middleware
    {
        consommer_commande(middleware, message, self).await
    }

    async fn consommer_evenement<M>(&self, middleware: &M, message: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where
        M: Middleware
    {
        consommer_evenement(middleware, self, message).await
    }
}

#[async_trait]
impl AiguillageTransactions for SenseursPassifsDomainManager {
    async fn aiguillage_transaction<M>(&self, middleware: &M, transaction: TransactionValide, session: &mut ClientSession)
        -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where
        M: ValidateurX509 + GenerateurMessages + MongoDao
    {
        aiguillage_transaction(self, middleware, transaction, session).await
    }
}

#[async_trait]
impl GestionnaireDomaineSimple for SenseursPassifsDomainManager {
    async fn traiter_cedule<M>(&self, middleware: &M, trigger: &MessageCedule) -> Result<(), CommonError>
    where
        M: MiddlewareMessages + BackupStarter + MongoDao
    {
        let minute = trigger.get_date().minute();

        // Faire l'aggretation des lectures
        // Va chercher toutes les lectures non traitees de l'heure precedente (-65 minutes)
        if minute % 15 == 5 {
            if let Err(e) = generer_transactions_lectures_horaires(middleware, self).await {
                error!("traiter_cedule Erreur generer_transactions : {:?}", e);
            }
        }

        if minute % 5 == 3 {
            if let Err(e) = mark_devices_offline(middleware).await {
                error!("traiter_cedule Error mark_devices_offline : {:?}", e);
            }
        }

        // if minute == 28 {
            if let Err(e) = maintain_device_certificates(middleware).await {
                error!("traiter_cedule Error maintain_device_certificates : {:?}", e);
            }
        //}

        Ok(())
    }

    async fn preparer_database_mongodb<M>(&self, middleware: &M) -> Result<(), CommonError>
    where
        M: MongoDao + ConfigMessages
    {
        // Handle transaction collection init being overridden
        if let Some(collection_name) = self.get_collection_transactions() {
            prepare_mongodb_domain_indexes(middleware, collection_name).await?;
        }
        preparer_index_mongodb(middleware).await?;  // Specialised indexes for domain collections
        Ok(())
    }

    async fn traitement_post_regeneration<M>(&self, middleware: &M) -> Result<(), CommonError>
    where
        M: Middleware
    {
        let mut session = middleware.get_session().await?;
        start_transaction_regular(&mut session).await?;
        match rebuild_sensor_list(middleware, &mut session).await {
            Ok(()) => session.commit_transaction().await?,
            Err(e) => {
                error!("traitement_post_regeneration Error rebuilding sensor list: {:?}", e);
                session.abort_transaction().await?;
                Err(e)?
            },
        }

        Ok(())
    }
}

pub fn preparer_queues(manager: &SenseursPassifsDomainManager) -> Vec<QueueType> {
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
        TRANSACTION_SHOW_HIDE_SENSOR,
        COMMANDE_INSCRIRE_APPAREIL,
        COMMANDE_CHALLENGE_APPAREIL,
        COMMANDE_SIGNER_APPAREIL,
        COMMANDE_CONFIRMER_RELAI,
        COMMANDE_RESET_CERTIFICATS,
        COMMAND_DISCONNECT_RELAY,
    ];
    for cmd in commandes_transactions {
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("commande.{}.{}", DOMAINE_NOM, cmd), exchange: Securite::L2Prive});
    }

    rk_volatils.push(ConfigRoutingExchange {
        routing_key: format!("commande.{}.{}.{}", DOMAINE_NOM, manager.instance_id.as_str(), TRANSACTION_LECTURE).into(),
        exchange: Securite::L2Prive
    });

    let mut queues = Vec::new();

    // Queue de messages volatils (requete, commande, evenements)
    queues.push(QueueType::ExchangeQueue (
        ConfigQueue {
            nom_queue: manager.get_q_volatils(),
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
        TRANSACTION_SHOW_HIDE_SENSOR,
    ];
    for trans in &transactions_sec {
        rk_transactions.push(ConfigRoutingExchange {
            routing_key: format!("transaction.{}.{}", DOMAINE_NOM, trans).into(),
            exchange: Securite::L4Secure,
        });
    }

    // // Queue de transactions
    // queues.push(QueueType::ExchangeQueue (
    //     ConfigQueue {
    //         nom_queue: gestionnaire.get_q_transactions().expect("get_q_transactions Ok").expect("get_q_transactions Some").into(),
    //         routing_keys: rk_transactions,
    //         ttl: None,
    //         durable: false,
    //         autodelete: false,
    //     }
    // ));

    // Queue de triggers
    queues.push(QueueType::Triggers (format!("{}", DOMAINE_NOM), Securite::L3Protege));

    queues

    // let mut rk_volatils = Vec::new();
    // //let mut rk_sauvegarder_cle = Vec::new();
    //
    // // RK 2.prive
    // let requetes_privees: Vec<&str> = vec![
    //     REQUEST_GET_CONVERSATION_KEYS,
    //     REQUEST_SYNC_CONVERSATIONS,
    //     REQUEST_SYNC_CONVERSATION_MESSAGES,
    // ];
    // for req in requetes_privees {
    //     rk_volatils.push(ConfigRoutingExchange {routing_key: format!("requete.{}.{}", DOMAIN_NAME, req), exchange: Securite::L2Prive});
    // }
    //
    // let commandes_privees: Vec<&str> = vec![
    //     COMMAND_CHAT_CONVERSATION_DELETE,
    // ];
    // for cmd in commandes_privees {
    //     rk_volatils.push(ConfigRoutingExchange {routing_key: format!("commande.{}.{}", DOMAIN_NAME, cmd), exchange: Securite::L2Prive});
    // }
    //
    // let commandes_protegees: Vec<&str> = vec![
    //     COMMAND_CHAT_EXCHANGE,
    // ];
    // for cmd in commandes_protegees {
    //     rk_volatils.push(ConfigRoutingExchange {routing_key: format!("commande.{}.{}", DOMAIN_NAME, cmd), exchange: Securite::L3Protege});
    // }
    //
    // let mut queues = Vec::new();
    //
    // // Queue de messages volatils (requete, commande, evenements)
    // queues.push(QueueType::ExchangeQueue (
    //     ConfigQueue {
    //         nom_queue: manager.get_q_volatils(),
    //         routing_keys: rk_volatils,
    //         ttl: DEFAULT_Q_TTL.into(),
    //         durable: true,
    //         autodelete: false,
    //     }
    // ));
    //
    // // Trigger Q
    // queues.push(QueueType::Triggers (DOMAIN_NAME.into(), Securite::L3Protege));
    //
    // queues
}

// pub async fn preparer_index_mongodb_custom<M>(_middleware: &M) -> Result<(), CommonError>
// where M: MongoDao + ConfigMessages
// {
//     // // Index fuuids pour fichiers (liste par tuuid)
//     // let options_unique_fuuids_versions = IndexOptions {
//     //     nom_index: Some(format!("fuuids_versions_user_id")),
//     //     unique: false
//     // };
//     // let champs_index_fuuids_version = vec!(
//     //     ChampIndex {nom_champ: String::from("fuuids_versions"), direction: 1},
//     //     ChampIndex {nom_champ: String::from("user_id"), direction: 1},
//     // );
//     // middleware.create_index(
//     //     middleware,
//     //     NOM_COLLECTION_FICHIERS_REP,
//     //     champs_index_fuuids_version,
//     //     Some(options_unique_fuuids_versions)
//     // ).await?;
//
//     Ok(())
// }

// pub async fn entretien<M>(_gestionnaire: &AiDomainManager, _middleware: Arc<M>)
// where M: Middleware + 'static
// {
//     loop {
//         sleep(Duration::new(30, 0)).await;
//         debug!("Cycle entretien {}", DOMAIN_NAME);
//     }
// }

// pub async fn traiter_cedule<M>(_gestionnaire: &SenseursPassifsDomainManager, middleware: &M, _trigger: &MessageCedule)
//                                -> Result<(), CommonError>
// where M: MiddlewareMessages
// {
//     debug!("Traiter cedule {}", DOMAIN_NAME);
//
//     if middleware.get_mode_regeneration() == true {
//         debug!("traiter_cedule Mode regeneration, skip");
//         return Ok(());
//     }
//
//     // let date_epoch = trigger.get_date();
//     // let minutes = date_epoch.minute();
//     // let hours = date_epoch.hour();
//
//     // Executer a intervalle regulier
//     // if minutes % 5 == 2 {
//     //     debug!("traiter_cedule Generer index et media manquants");
//     //     gestionnaire.image_job_handler.entretien(middleware, gestionnaire, None).await;
//     //     gestionnaire.video_job_handler.entretien(middleware, gestionnaire, None).await;
//     //     gestionnaire.indexation_job_handler.entretien(middleware, gestionnaire, None).await;
//     // }
//     //
//     // // Recalculer les quotas a toutes les 3 heures
//     // if hours % 3 == 1 && minutes == 14 {
//     //     calculer_quotas(middleware).await;
//     // }
//
//     Ok(())
// }
