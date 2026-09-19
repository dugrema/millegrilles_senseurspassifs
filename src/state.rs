use crate::flow::app_service::ApplicationService;
use crate::flow::transactions::SenseursPassifsTransactionService;
use millegrilles_common_rust::certificats::build_store_path_v2;
use millegrilles_common_rust::chiffrage_cle::CleChiffrageHandlerImpl;
use millegrilles_common_rust::configuration::{ConfigDb, ConfigMessages, charger_configuration, charger_configuration_mongo};
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::mongo_dao::{MongoDaoImpl, initialiser};
use millegrilles_common_rust::tokio::task::JoinSet;
use millegrilles_common_rust::tokio_util::sync::CancellationToken;
use millegrilles_common_rust::tracing::{debug, info};
use millegrilles_common_rust::v3::ConfigService;
use millegrilles_common_rust::v3::facades::message_inbound::MessageInboundValidator;
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;
use millegrilles_common_rust::v3::impls::config_service::ConfigServiceDbImpl;
use millegrilles_common_rust::v3::impls::format_service::FormatServiceImpl;
use millegrilles_common_rust::v3::impls::messaging_service::MessagingServiceImpl;
use millegrilles_common_rust::v3::impls::security_service::SecurityServiceImpl;
use std::sync::Arc;

/// Composition object with services from common library
pub struct AppContext {
    pub join_set: JoinSet<()>,
    pub config: Arc<dyn ConfigService>,
    pub mongo: Arc<MongoDaoImpl>,
    pub outbound: Arc<MessageOutboundFacade>,
    pub shutdown_token: CancellationToken,
}

impl AppContext {
    pub async fn new() -> Result<Self, CommonError> {
        // Shutdown/cancel semantics
        let shutdown_token = CancellationToken::new();
        let mut join_set = JoinSet::new();

        // Basic services
        let config = Arc::new(init_config().await?);
        let security = Arc::new(init_security(config.as_ref()).await?);
        let messaging = Arc::new(MessagingServiceImpl::new(config.clone(), security.clone()));
        let format = Arc::new(FormatServiceImpl::new(config.clone()));

        let mongo = Arc::new(
            initialiser(config.get_configuration_pki(), config.get_configuraiton_mongo())?
        );

        // Facades
        let outbound = Arc::new(
            MessageOutboundFacade::new(config.clone(), messaging.clone(), format.clone(), security.clone()));
        let inbound = Arc::new(
            MessageInboundValidator::new(config.clone(), messaging.clone(), security.clone(), shutdown_token.clone())
        );

        let transaction = Arc::new(SenseursPassifsTransactionService::new(
            config.clone(),
            format.clone(),
            mongo.clone(),
        ));

        let app_service = Arc::new(ApplicationService::new(security.clone(), outbound.clone(), transaction.clone(), mongo.clone()));

        info!("Configure middleware resources : queues, index, tables, ...");
        app_service.configure(messaging.as_ref(), config.as_ref()).await?;

        info!("Connect services, start maintenance threads");
        start_threads(
            &mut join_set,
            security.clone(),
            messaging.as_ref(),
            inbound.clone(),
            app_service.clone(),
            shutdown_token.clone(),
        ).await?;


        Ok(AppContext {
            join_set,
            config: config.clone(),
            mongo,
            outbound,
            shutdown_token,
        })
    }
}

async fn init_config() -> Result<ConfigServiceDbImpl, CommonError> {
    let config = charger_configuration()?;
    let mongo = charger_configuration_mongo(config.get_configuration_pki())?;
    Ok(ConfigServiceDbImpl::new(Arc::new(config), Arc::new(mongo)))
}


async fn init_security(config: &dyn ConfigService) -> Result<SecurityServiceImpl, CommonError> {
    let validator = build_store_path_v2(&config.get_configuration_pki().ca_certfile).map_err(|e| e.to_string())?;
    let private_key = config.get_configuration_pki().get_enveloppe_privee();

    let security_impl = SecurityServiceImpl::new(
        private_key,
        Arc::new(validator),
        Arc::new(CleChiffrageHandlerImpl::new()),
    );

    Ok(security_impl)
}

async fn start_threads(
    join_set: &mut JoinSet<()>,
    security: Arc<SecurityServiceImpl>,
    messaging: &MessagingServiceImpl,
    incoming: Arc<MessageInboundValidator>,
    app_service: Arc<ApplicationService>,
    shutdown_token: CancellationToken,
) -> Result<(), CommonError> {

    // Connect to RabbitMQ (throws error on failure).
    // This also spawns all other required threads.
    messaging.start(join_set, shutdown_token.clone()).await?;
    debug!("Started messaging service, connection OK");

    // Spawn other service maintenance threads
    let shutdown_token_clone = shutdown_token.clone();
    join_set.spawn(async move { security.run(shutdown_token_clone).await });

    // Spawn consumer threads
    app_service.start(join_set, incoming.clone())?;

    Ok(())
}
