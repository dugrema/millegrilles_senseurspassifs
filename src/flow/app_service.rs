use crate::common::DOMAINE_NOM;
use crate::external::mongo::create_index_mongodb;
use crate::external::mq::*;
use crate::flow::commands::{process_backup, process_command, process_transaction};
use crate::flow::maintenance::process_ticker_job;
use crate::flow::readings::process_reading;
use crate::flow::requests::{process_device_request, process_request};
use crate::flow::requests_reports::process_report;
use crate::flow::transactions::SenseursPassifsTransactionService;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::mongo_dao::MongoDaoImpl;
use millegrilles_common_rust::tokio;
use millegrilles_common_rust::tokio::task::JoinSet;
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::tracing::{debug, error};
use millegrilles_common_rust::v3::{BackupService, PkiService};
use millegrilles_common_rust::v3::facades::message_inbound::MessageInboundValidator;
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;
use millegrilles_common_rust::v3::impls::config_service::ConfigServiceDbImpl;
use millegrilles_common_rust::v3::impls::messaging_service::MessagingServiceImpl;
use std::sync::Arc;

/// Handles queue consumer threads, calls individual routing methods
pub struct ApplicationService {
    pki: Arc<dyn PkiService>,
    outbound: Arc<MessageOutboundFacade>,
    transaction: Arc<SenseursPassifsTransactionService>,
    mongo: Arc<MongoDaoImpl>,
    backup: Arc<dyn BackupService>,
}

impl ApplicationService {
    pub fn new(
        pki: Arc<dyn PkiService>,
        outbound: Arc<MessageOutboundFacade>,
        transaction: Arc<SenseursPassifsTransactionService>,
        mongo: Arc<MongoDaoImpl>,
        backup: Arc<dyn BackupService>,
    ) -> Self {
        Self {
            pki,
            outbound,
            transaction,
            mongo,
            backup,
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

        let self_clone = self.clone();
        let incoming_clone = incoming.clone();
        join_set.spawn(async move {self_clone.process_backup_thread(incoming_clone).await});
        
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
                        self.backup.as_ref(),
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
                        self.pki.as_ref(),
                        self.mongo.as_ref(),
                        self.outbound.as_ref(),
                        self.transaction.as_ref(),
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

    async fn process_backup_thread(&self, incoming: Arc<MessageInboundValidator>) {
        let streamer = incoming.consume_named_queue(
            format!("{}/{}", DOMAINE_NOM, QUEUE_BACKUP).as_str(),
        ).expect("Consumer streaming init failed");
        tokio::pin!(streamer);
        while let Some(result) = streamer.next().await {
            match result {
                Ok(message) => {
                    if let Err(e) = process_backup(
                        self.outbound.as_ref(),
                        self.backup.as_ref(),
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
