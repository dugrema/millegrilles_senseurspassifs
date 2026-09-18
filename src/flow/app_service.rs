use std::sync::Arc;
use millegrilles_common_rust::certificats::VerificateurPermissions;
use millegrilles_common_rust::chrono::{Datelike, Duration, Timelike, Utc};
use millegrilles_common_rust::constantes::Securite;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::messages_generiques::MessageCedule;
use millegrilles_common_rust::mongo_dao::{MongoDao, MongoDaoImpl, MongoDaoTyped};
use millegrilles_common_rust::tokio;
use millegrilles_common_rust::tokio::task::JoinSet;
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::tracing::{debug, error, info, warn};
use millegrilles_common_rust::v3::facades::message_inbound::{MessageInboundValidator, MessageValidated};
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;
use millegrilles_common_rust::v3::impls::config_service::ConfigServiceDbImpl;
use millegrilles_common_rust::v3::impls::messaging_service::MessagingServiceImpl;
use millegrilles_common_rust::v3::models::ErrorMessage;
use millegrilles_common_rust::v3::{PkiService, PresenceService};
use crate::common::{DOMAINE_NOM, EVENEMENT_LECTURE, ROLE_RELAI_NOM};
use crate::external::mongo::create_index_mongodb;
use crate::external::mq::{init_queues, QUEUE_TICKER, QUEUE_REQUESTS, QUEUE_REPORTS, QUEUE_DEVICE_REQUESTS, QUEUE_COMMANDS, QUEUE_TRANSACTIONS, QUEUE_READINGS};
use crate::flow::readings::{generate_readings_for_transactions, process_reading_event};
use crate::flow::requests::*;
use crate::flow::commands::*;
use crate::flow::events::*;
use crate::flow::maintenance::mark_devices_offline;
use crate::flow::transactions::*;
use crate::flow::requests_reports::send_device_report;

pub struct ApplicationService {
    pki: Arc<dyn PkiService>,
    outbound: Arc<MessageOutboundFacade>,
    transaction: Arc<SenseursPassifsTransactionService>,
    mongo: Arc<MongoDaoImpl>,
}

impl ApplicationService {
    pub fn new(
        pki: Arc<dyn PkiService>,
        outbound: Arc<MessageOutboundFacade>,
        transaction: Arc<SenseursPassifsTransactionService>,
        mongo: Arc<MongoDaoImpl>,
    ) -> Self {
        Self {
            pki,
            outbound,
            transaction,
            mongo,
        }
    }

    pub async fn configure(&self, mq: &MessagingServiceImpl, config: &ConfigServiceDbImpl) -> Result<(), CommonError> {
        init_queues(mq)?;
        create_index_mongodb(self.mongo.as_ref(), config.config.as_ref()).await?;
        Ok(())
    }

    /// Call to spawn the consumer threads
    pub fn start(self: Arc<Self>, join_set: &mut JoinSet<()>, incoming: Arc<MessageInboundValidator>) -> Result<(), CommonError> {
        let self_clone = self.clone();
        let incoming_clone = incoming.clone();
        join_set.spawn(async move {self_clone.process_ticker_thread(incoming_clone).await});

        let self_clone = self.clone();
        let incoming_clone = incoming.clone();
        join_set.spawn(async move {self_clone.process_requests_thread(incoming_clone).await});

        let self_clone = self.clone();
        let incoming_clone = incoming.clone();
        join_set.spawn(async move {self_clone.process_reports_thread(incoming_clone).await});

        let self_clone = self.clone();
        let incoming_clone = incoming.clone();
        join_set.spawn(async move {self_clone.process_device_requests_thread(incoming_clone).await});

        let self_clone = self.clone();
        let incoming_clone = incoming.clone();
        join_set.spawn(async move {self_clone.process_commands_thread(incoming_clone).await});

        let self_clone = self.clone();
        let incoming_clone = incoming.clone();
        join_set.spawn(async move {self_clone.process_transaction_thread(incoming_clone).await});

        let self_clone = self.clone();
        let incoming_clone = incoming.clone();
        join_set.spawn(async move {self_clone.process_readings_thread(incoming_clone).await});

        Ok(())
    }

    async fn process_ticker_thread(&self, incoming: Arc<MessageInboundValidator>) {
        let streamer = incoming.consume_named_queue(
            format!("{}/{}", DOMAINE_NOM, QUEUE_TICKER).as_str(),
        ).expect("Consumer streaming init failed");
        tokio::pin!(streamer);
        while let Some(result) = streamer.next().await {
            match result {
                Ok(message) => {
                    if let Err(e) = process_ticker_job(
                        self.mongo.as_ref(),
                        self.outbound.as_ref(),
                        self.transaction.as_ref(),
                        message
                    ).await {
                        error!("Ticker job failed: {}", e);
                    }
                }
                Err(e) => {
                    error!("Error processing ticker message: {}", e);
                }
            }
        }
        debug!("process_ticker_thread Closed");
    }

    // Requests
    async fn process_requests_thread(&self, incoming: Arc<MessageInboundValidator>) {
        let streamer = incoming.consume_named_queue(
            format!("{}/{}", DOMAINE_NOM, QUEUE_REQUESTS).as_str(),
        ).expect("Consumer streaming init failed");
        tokio::pin!(streamer);
        while let Some(result) = streamer.next().await {
            match result {
                Ok(message) => {
                    if let Err(e) = process_request(
                        self.mongo.as_ref(),
                        self.outbound.as_ref(),
                        message
                    ).await {
                        error!("Ticker job failed: {}", e);
                    }
                }
                Err(e) => {
                    error!("Error processing request message: {}", e);
                }
            }
        }
        debug!("process_requests_thread Closed");
    }

    // Reports
    async fn process_reports_thread(&self, incoming: Arc<MessageInboundValidator>) {
        let streamer = incoming.consume_named_queue(
            format!("{}/{}", DOMAINE_NOM, QUEUE_REPORTS).as_str(),
        ).expect("Consumer streaming init failed");
        tokio::pin!(streamer);
        while let Some(result) = streamer.next().await {
            match result {
                Ok(message) => {
                    if let Err(e) = process_report(
                        self.mongo.as_ref(),
                        self.outbound.as_ref(),
                        message
                    ).await {
                        error!("Report job failed: {}", e);
                    }
                }
                Err(e) => {
                    error!("Error processing report message: {}", e);
                }
            }
        }
        debug!("process_reports_thread Closed");
    }

    // Device requests
    async fn process_device_requests_thread(&self, incoming: Arc<MessageInboundValidator>) {
        let streamer = incoming.consume_named_queue(
            format!("{}/{}", DOMAINE_NOM, QUEUE_DEVICE_REQUESTS).as_str(),
        ).expect("Consumer streaming init failed");
        tokio::pin!(streamer);
        while let Some(result) = streamer.next().await {
            match result {
                Ok(message) => {
                    if let Err(e) = process_device_request(
                        self.mongo.as_ref(),
                        self.outbound.as_ref(),
                        message
                    ).await {
                        error!("Device request job failed: {}", e);
                    }
                }
                Err(e) => {
                    error!("Error processing device request message: {}", e);
                }
            }
        }
        debug!("process_device_requests_thread Closed");
    }

    // Commands
    async fn process_commands_thread(&self, incoming: Arc<MessageInboundValidator>) {
        let streamer = incoming.consume_named_queue(
            format!("{}/{}", DOMAINE_NOM, QUEUE_COMMANDS).as_str(),
        ).expect("Consumer streaming init failed");
        tokio::pin!(streamer);
        while let Some(result) = streamer.next().await {
            match result {
                Ok(message) => {
                    if let Err(e) = process_command(
                        self.mongo.as_ref(),
                        self.outbound.as_ref(),
                        message
                    ).await {
                        error!("Command job failed: {}", e);
                    }
                }
                Err(e) => {
                    error!("Error processing command message: {}", e);
                }
            }
        }
        debug!("process_commands_thread Closed");
    }

    // Transactions
    async fn process_transaction_thread(&self, incoming: Arc<MessageInboundValidator>) {
        let streamer = incoming.consume_named_queue(
            format!("{}/{}", DOMAINE_NOM, QUEUE_TRANSACTIONS).as_str(),
        ).expect("Consumer streaming init failed");
        tokio::pin!(streamer);
        while let Some(result) = streamer.next().await {
            match result {
                Ok(message) => {
                    if let Err(e) = process_transaction(
                        self.mongo.as_ref(),
                        self.outbound.as_ref(),
                        self.transaction.as_ref(),
                        message
                    ).await {
                        error!("Transaction job failed: {}", e);
                    }
                }
                Err(e) => {
                    error!("Error processing transaction message: {}", e);
                }
            }
        }
        debug!("process_transaction_thread Closed");
    }

    // Readings
    async fn process_readings_thread(&self, incoming: Arc<MessageInboundValidator>) {
        let streamer = incoming.consume_named_queue(
            format!("{}/{}", DOMAINE_NOM, QUEUE_READINGS).as_str(),
        ).expect("Consumer streaming init failed");
        tokio::pin!(streamer);
        while let Some(result) = streamer.next().await {
            match result {
                Ok(message) => {
                    if let Err(e) = process_reading(
                        self.pki.as_ref(),
                        self.mongo.as_ref(),
                        self.outbound.as_ref(),
                        message
                    ).await {
                        error!("Reading job failed: {}", e);
                    }
                }
                Err(e) => {
                    error!("Error processing reading message: {}", e);
                }
            }
        }
        debug!("process_readings_thread Closed");
    }

}

async fn process_ticker_job<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    transaction: &SenseursPassifsTransactionService,
    trigger: MessageValidated
) -> Result<(), CommonError> where M: MongoDaoTyped
{
    // Ensure this is an authorized module
    if let Err(e) = validate_ticker(&trigger).await {
        error!("Invalid ticker message, rejecting: {}", e);
        return Ok(());
    }

    let trigger_value: MessageCedule = trigger.message.deserialize()?;

    let hour = trigger_value.get_date().hour();
    let minute = trigger_value.get_date().minute();
    let day = trigger_value.get_date().weekday();

    debug!("ticker_job_ca for h:{} m:{}",hour,minute);

    // Emit domain presence
    if let Err(e) = outbound.emit_domain_presence(DOMAINE_NOM, None).await {
        warn!("Error emitting domain presence: {}", e);
    }

    if minute % 2 == 0 {
        if let Err(e) = mark_devices_offline(mongo, outbound).await {
            error!("Error mark_devices_offline : {:?}", e);
        }
    }

    // if minute % 10 == 2 {
    {
        // Aggregate readings into transactions
        if let Err(e) = generate_readings_for_transactions(mongo, transaction).await {
            error!("Error generating readings transactions: {:?}", e);
        }
    }

    //         if minute == 28 && heure % 12 == 4 {
    //             if let Err(e) = maintain_device_certificates(middleware).await {
    //                 error!("traiter_cedule Error maintain_device_certificates : {:?}", e);
    //             }
    //         }

    Ok(())
}

pub const ROLE_TICKER: &str = "ceduleur";

pub async fn validate_ticker(trigger: &MessageValidated) -> Result<(), CommonError> {
    if let Ok(true) = trigger.certificate.verifier_roles_string(vec![ROLE_TICKER.to_string()]) {
        // Ok
    } else {
        return Err(CommonError::Str("Ticker message without ticker (ceduleur) role, ignoring"));
    }
    if trigger.message.estampille < Utc::now() - Duration::seconds(45) {
        debug!("Expired Ticker message, ignoring");
        return Err(CommonError::Str("Ticker message without ticker (ceduleur) role, ignoring"));
    }
    Ok(())
}

async fn process_request<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated
) -> Result<(), CommonError> where M: MongoDaoTyped {
    let action = match wrapper.get_routing_action() {
        Some(action) => action,
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err("No action provided in request")).await
    };
    match action {
        REQUETE_GET_APPAREILS_USAGER => get_user_devices(mongo, outbound, wrapper).await,
        REQUETE_LISTE_NOEUDS => todo!(),
        REQUETE_GET_NOEUD => todo!(),
        REQUETE_LISTE_SENSEURS_PAR_UUID => todo!(),
        REQUETE_LISTE_SENSEURS_NOEUD => todo!(),
        REQUETE_GET_APPAREILS_EN_ATTENTE => todo!(),
        REQUETE_GET_APPAREIL_DISPLAY_CONFIGURATION => get_device_display_configuration(mongo, outbound, wrapper).await,
        REQUETE_GET_APPAREIL_PROGRAMMES_CONFIGURATION => get_device_program_configuration(mongo, outbound, wrapper).await,
        REQUETE_GET_CONFIGURATION_USAGER => get_user_configuration(mongo, outbound, wrapper).await,
        _ => {
            info!("Unknown action {} for process_request, skipping", action);
            Ok(())
        }
    }
}

async fn process_report(
    mongo: &dyn MongoDao,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated
) -> Result<(), CommonError> {
    let action = match wrapper.get_routing_action() {
        Some(action) => action,
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err("No action provided in request")).await
    };
    match action {
        REQUETE_GET_STATISTIQUES_SENSEUR => send_device_report(mongo, outbound, wrapper).await,
        _ => {
            info!("Unknown action {} for process_request, skipping", action);
            Ok(())
        }
    }
}

async fn process_device_request<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated
) -> Result<(), CommonError> where M: MongoDaoTyped {
    let action = match wrapper.get_routing_action() {
        Some(action) => action,
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err("No action provided in request")).await
    };
    match action {
        REQUETE_GET_TIMEZONE_APPAREIL => get_device_timezone(mongo, outbound, wrapper).await,
        _ => {
            info!("Unknown action {} for process_request, skipping", action);
            Ok(())
        }
    }
}

async fn process_command<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated
) -> Result<(), CommonError> where M: MongoDaoTyped {
    let action = match wrapper.get_routing_action() {
        Some(action) => action,
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err("No action provided in command")).await
    };

    match action {
        COMMANDE_INSCRIRE_APPAREIL => todo!(),
        COMMANDE_CHALLENGE_APPAREIL => todo!(),
        COMMANDE_SIGNER_APPAREIL => todo!(),
        COMMANDE_CONFIRMER_RELAI => confirm_relai(mongo, outbound, wrapper).await,
        COMMANDE_RESET_CERTIFICATS => todo!(),
        COMMAND_DISCONNECT_RELAY => todo!(),
        EVENEMENT_PRESENCE_APPAREIL => device_presence_event(mongo, outbound, wrapper).await,
        _ => {
            info!("Unknown action {} for process_command, skipping", action);
            Ok(())
        }
    }
}

async fn process_transaction<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    transaction: &SenseursPassifsTransactionService,
    wrapper: MessageValidated
) -> Result<(), CommonError> where M: MongoDaoTyped {
    let action = match wrapper.get_routing_action() {
        Some(action) => action,
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err("No action provided in command")).await
    };
    match action {
        TRANSACTION_LECTURE => todo!(),
        TRANSACTION_MAJ_SENSEUR => todo!(),
        TRANSACTION_MAJ_NOEUD => todo!(),
        TRANSACTION_SUPPRESSION_SENSEUR => todo!(),
        TRANSACTION_MAJ_APPAREIL => update_device_command(mongo, outbound, transaction, wrapper).await,
        TRANSACTION_SAUVEGARDER_PROGRAMME => todo!(),
        TRANSACTION_APPAREIL_SUPPRIMER => todo!(),
        TRANSACTION_APPAREIL_RESTAURER => todo!(),
        TRANSACTION_MAJ_CONFIGURATION_USAGER => todo!(),
        TRANSACTION_SHOW_HIDE_SENSOR => todo!(),
        _ => {
            info!("Unknown action {} for process_transaction, skipping", action);
            Ok(())
        }
    }
}

async fn process_reading<M>(
    pki: &dyn PkiService,
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated
) -> Result<(), CommonError> where M: MongoDaoTyped {
    let action = match wrapper.get_routing_action() {
        Some(action) => action,
        None => {
            debug!("No action provided in event {}, skipped", wrapper.message.id);
            return Ok(())
        }
    };

    if ! wrapper.certificate.verifier_exchanges(vec![Securite::L2Prive])? &&
        !wrapper.certificate.verifier_roles_string(vec![ROLE_RELAI_NOM.to_string()])?
    {
        debug!("Unauthorized message {} in process_reading, skipped", wrapper.message.id);
        return Ok(())
    }

    match action {
        EVENEMENT_LECTURE => process_reading_event(pki, mongo, outbound, wrapper).await,
        _ => {
            info!("Unknown action {} for process_request, skipping", action);
            Ok(())
        }
    }
}
