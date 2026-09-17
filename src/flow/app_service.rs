use std::sync::Arc;
use millegrilles_common_rust::certificats::VerificateurPermissions;
use millegrilles_common_rust::chrono::{Datelike, Duration, Timelike, Utc};
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::messages_generiques::MessageCedule;
use millegrilles_common_rust::mongo_dao::{MongoDaoImpl, MongoDaoTyped};
use millegrilles_common_rust::tokio;
use millegrilles_common_rust::tokio::task::JoinSet;
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::tracing::{debug, error, warn};
use millegrilles_common_rust::v3::facades::message_inbound::{MessageInboundValidator, MessageValidated};
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;
use millegrilles_common_rust::v3::impls::config_service::ConfigServiceDbImpl;
use millegrilles_common_rust::v3::impls::messaging_service::MessagingServiceImpl;
use millegrilles_common_rust::v3::PresenceService;
use crate::common::DOMAINE_NOM;
use crate::external::mongo::create_index_mongodb;
use crate::external::mq::{init_queues, QUEUE_TICKER};
use crate::flow::transactions::SenseursPassifsTransactionService;

pub struct ApplicationService {
    outbound: Arc<MessageOutboundFacade>,
    transaction: Arc<SenseursPassifsTransactionService>,
    mongo: Arc<MongoDaoImpl>,
}

impl ApplicationService {
    pub fn new(
        outbound: Arc<MessageOutboundFacade>,
        transaction: Arc<SenseursPassifsTransactionService>,
        mongo: Arc<MongoDaoImpl>,
    ) -> Self {
        Self {
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


        todo!()
    }

    async fn process_ticker_thread(&self, incoming: Arc<MessageInboundValidator>) {
        let streamer = incoming.consume_named_queue(
            format!("{}/{}", DOMAINE_NOM, QUEUE_TICKER).as_str(),
        ).expect("Consumer streaming init failed");
        tokio::pin!(streamer);
        while let Some(result) = streamer.next().await {
            match result {
                Ok(message) => {
                    if let Err(e) = ticker_job(
                        self.mongo.as_ref(),
                        self.outbound.as_ref(),
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
}

async fn ticker_job<M>(
    _mongo: &M,
    presence: &dyn PresenceService,
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
    if let Err(e) = presence.emit_domain_presence(DOMAINE_NOM, None).await {
        warn!("Error emitting domain presence: {}", e);
    }

    //         // Faire l'aggretation des lectures
    //         // Va chercher toutes les lectures non traitees de l'heure precedente (-65 minutes)
    //         if minute % 15 == 5 {
    //             if let Err(e) = generer_transactions_lectures_horaires(middleware, self).await {
    //                 error!("traiter_cedule Erreur generer_transactions : {:?}", e);
    //             }
    //         }
    //
    //         if minute % 5 == 3 {
    //             if let Err(e) = mark_devices_offline(middleware).await {
    //                 error!("traiter_cedule Error mark_devices_offline : {:?}", e);
    //             }
    //         }
    //
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
