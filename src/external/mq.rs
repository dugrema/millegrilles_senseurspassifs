use millegrilles_common_rust::constantes::{Securite, COMMANDE_DECLENCHER_BACKUP, COMMANDE_GLOBAL_DECLENCHER_BACKUP, COMMANDE_REGENERER};
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::rabbitmq_dao::{ConfigQueue, ConfigRoutingExchange};
use millegrilles_common_rust::v3::impls::messaging_service::MessagingServiceImpl;
use crate::common::*;
use crate::flow::commands::{COMMANDE_CHALLENGE_APPAREIL, COMMANDE_CONFIRMER_RELAI, COMMANDE_INSCRIRE_APPAREIL, COMMANDE_RESET_CERTIFICATS, COMMANDE_SIGNER_APPAREIL, COMMAND_DISCONNECT_RELAY};
use crate::flow::requests::{REQUETE_GET_APPAREILS_EN_ATTENTE, REQUETE_GET_APPAREILS_USAGER, REQUETE_GET_APPAREIL_DISPLAY_CONFIGURATION, REQUETE_GET_APPAREIL_PROGRAMMES_CONFIGURATION, REQUETE_GET_CONFIGURATION_USAGER, REQUETE_GET_NOEUD, REQUETE_GET_STATISTIQUES_SENSEUR, REQUETE_GET_TIMEZONE_APPAREIL, REQUETE_LISTE_NOEUDS, REQUETE_LISTE_SENSEURS_NOEUD, REQUETE_LISTE_SENSEURS_PAR_UUID};
use crate::flow::transactions::*;

pub const QUEUE_TTL_DEFAULT: u32 = 30_000;
pub const QUEUE_REPORT_TTL: u32 = 180_000;
pub const QUEUE_DEVICE_TTL: u32 = 20_000;
pub const QUEUE_DEVICE_READING_TTL: u32 = 12 * 3_600_000;  // 12 hours, try to recover sensor readings on best effort
pub const QUEUE_TICKER: &str = "job_ticker";
pub const QUEUE_REQUESTS: &str = "requests";
pub const QUEUE_REPORTS: &str = "reports";
pub const QUEUE_DEVICE_REQUESTS: &str = "device_requests";
pub const QUEUE_COMMANDS: &str = "commands";
pub const QUEUE_TRANSACTIONS: &str = "transactions";
pub const QUEUE_READINGS: &str = "readings";
pub const QUEUE_BACKUP: &str = "backup";

pub fn init_queues(mq: &MessagingServiceImpl) -> Result<(), CommonError> {
    // Configure the queues and add to messaging service (will spawn consumer threads)
    mq.add_named_queue(
        ConfigQueue {
            nom_queue: format!("{}/{}", DOMAINE_NOM, QUEUE_TICKER),
            routing_keys: vec![
                ConfigRoutingExchange { routing_key: "evenement.ceduleur.ping".to_string(), exchange: Securite::L1Public }
            ],
            ttl: Some(QUEUE_TTL_DEFAULT),
            durable: true,
            autodelete: true,
        })?;

    mq.add_named_queue(
        ConfigQueue {
            nom_queue: format!("{}/{}", DOMAINE_NOM, QUEUE_REQUESTS),
            routing_keys: vec![
                ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, REQUETE_GET_APPAREILS_USAGER), exchange: Securite::L2Prive },
                ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, REQUETE_GET_APPAREIL_DISPLAY_CONFIGURATION), exchange: Securite::L2Prive },
                ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, REQUETE_GET_APPAREIL_PROGRAMMES_CONFIGURATION), exchange: Securite::L2Prive },
                ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, REQUETE_LISTE_NOEUDS), exchange: Securite::L2Prive },
                ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, REQUETE_GET_NOEUD), exchange: Securite::L2Prive },
                ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, REQUETE_LISTE_SENSEURS_PAR_UUID), exchange: Securite::L2Prive },
                ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, REQUETE_LISTE_SENSEURS_NOEUD), exchange: Securite::L2Prive },
                ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, REQUETE_GET_APPAREILS_EN_ATTENTE), exchange: Securite::L2Prive },
                ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, REQUETE_GET_CONFIGURATION_USAGER), exchange: Securite::L2Prive },
            ],
            ttl: Some(QUEUE_TTL_DEFAULT),
            durable: true,
            autodelete: false,
        })?;

    mq.add_named_queue(
        ConfigQueue {
            nom_queue: format!("{}/{}", DOMAINE_NOM, QUEUE_REPORTS),
            routing_keys: vec![
                ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, REQUETE_GET_STATISTIQUES_SENSEUR), exchange: Securite::L2Prive },
            ],
            ttl: Some(QUEUE_REPORT_TTL),
            durable: true,
            autodelete: false,
        })?;

    mq.add_named_queue(
        ConfigQueue {
            nom_queue: format!("{}/{}", DOMAINE_NOM, QUEUE_DEVICE_REQUESTS),
            routing_keys: vec![
                ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, REQUETE_GET_TIMEZONE_APPAREIL), exchange: Securite::L2Prive },
            ],
            ttl: Some(QUEUE_DEVICE_TTL),
            durable: true,
            autodelete: false,
        })?;

    mq.add_named_queue(
        ConfigQueue {
            nom_queue: format!("{}/{}", DOMAINE_NOM, QUEUE_COMMANDS),
            routing_keys: vec![
                ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, COMMANDE_INSCRIRE_APPAREIL), exchange: Securite::L2Prive },
                ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, COMMANDE_CHALLENGE_APPAREIL), exchange: Securite::L2Prive },
                ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, COMMANDE_SIGNER_APPAREIL), exchange: Securite::L2Prive },
                ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, COMMANDE_CONFIRMER_RELAI), exchange: Securite::L2Prive },
                ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, COMMANDE_RESET_CERTIFICATS), exchange: Securite::L2Prive },
                ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, COMMAND_DISCONNECT_RELAY), exchange: Securite::L2Prive },
                ConfigRoutingExchange { routing_key: format!("evenement.{}.{}", DOMAINE_NOM, EVENEMENT_PRESENCE_APPAREIL), exchange: Securite::L2Prive },
                ConfigRoutingExchange { routing_key: format!("evenement.{}.{}", ROLE_RELAI_NOM, EVENEMENT_PRESENCE_APPAREIL), exchange: Securite::L2Prive },
            ],
            ttl: Some(QUEUE_TTL_DEFAULT),
            durable: true,
            autodelete: false,
        })?;

    mq.add_named_queue(
        ConfigQueue {
            nom_queue: format!("{}/{}", DOMAINE_NOM, QUEUE_TRANSACTIONS),
            routing_keys: vec![
                ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, TRANSACTION_MAJ_SENSEUR), exchange: Securite::L2Prive },
                ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, TRANSACTION_MAJ_NOEUD), exchange: Securite::L2Prive },
                ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, TRANSACTION_SUPPRESSION_SENSEUR), exchange: Securite::L2Prive },
                ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, TRANSACTION_MAJ_APPAREIL), exchange: Securite::L2Prive },
                ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, TRANSACTION_SAUVEGARDER_PROGRAMME), exchange: Securite::L2Prive },
                ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, TRANSACTION_APPAREIL_SUPPRIMER), exchange: Securite::L2Prive },
                ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, TRANSACTION_APPAREIL_RESTAURER), exchange: Securite::L2Prive },
                ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, TRANSACTION_MAJ_CONFIGURATION_USAGER), exchange: Securite::L2Prive },
                ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, TRANSACTION_SHOW_HIDE_SENSOR), exchange: Securite::L2Prive },

                //     rk_volatils.push(ConfigRoutingExchange {
                //         routing_key: format!("commande.{}.{}.{}", DOMAINE_NOM, manager.instance_id.as_str(), TRANSACTION_LECTURE).into(),
                //         exchange: Securite::L2Prive
                //     });
            ],
            ttl: Some(QUEUE_TTL_DEFAULT),
            durable: true,
            autodelete: false,
        })?;

    mq.add_named_queue(
        ConfigQueue {
            nom_queue: format!("{}/{}", DOMAINE_NOM, QUEUE_READINGS),
            routing_keys: vec![
                ConfigRoutingExchange { routing_key: format!("evenement.{}.{}", DOMAINE_NOM, EVENEMENT_LECTURE), exchange: Securite::L2Prive },
                ConfigRoutingExchange { routing_key: format!("evenement.{}.{}", ROLE_RELAI_NOM, EVENEMENT_LECTURE), exchange: Securite::L2Prive },
            ],
            ttl: Some(QUEUE_DEVICE_READING_TTL),
            durable: true,
            autodelete: false,
        })?;

    mq.add_named_queue(ConfigQueue {
        nom_queue: format!("{}/{}", DOMAINE_NOM, QUEUE_BACKUP),
        routing_keys: vec![
            ConfigRoutingExchange { routing_key: format!("requete.{}.getNombreTransactions", DOMAINE_NOM), exchange: Securite::L2Prive },
            ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, COMMANDE_DECLENCHER_BACKUP), exchange: Securite::L3Protege },
            ConfigRoutingExchange { routing_key: COMMANDE_GLOBAL_DECLENCHER_BACKUP.to_string(), exchange: Securite::L3Protege },
            ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, COMMANDE_REGENERER), exchange: Securite::L3Protege },
        ],
        ttl: Some(QUEUE_TTL_DEFAULT),
        durable: true,
        autodelete: true,
    })?;


    Ok(())
}
