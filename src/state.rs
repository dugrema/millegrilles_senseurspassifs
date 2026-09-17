use std::sync::Arc;
use millegrilles_common_rust::certificats::build_store_path_v2;
use millegrilles_common_rust::chiffrage_cle::CleChiffrageHandlerImpl;
use millegrilles_common_rust::configuration::{charger_configuration, ConfigMessages, charger_configuration_mongo, ConfigDb};
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::mongo_dao::{initialiser, MongoDaoImpl};
use millegrilles_common_rust::tokio::task::JoinSet;
use millegrilles_common_rust::tokio_util::sync::CancellationToken;
use millegrilles_common_rust::tracing::debug;
use millegrilles_common_rust::v3::{ChiffrageService, ConfigService};
use millegrilles_common_rust::v3::facades::message_inbound::MessageInboundValidator;
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;
use millegrilles_common_rust::v3::impls::config_service::ConfigServiceDbImpl;
use millegrilles_common_rust::v3::impls::format_service::FormatServiceImpl;
use millegrilles_common_rust::v3::impls::messaging_service::MessagingServiceImpl;
use millegrilles_common_rust::v3::impls::security_service::SecurityServiceImpl;

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
    let encryption_key = private_key.enveloppe_pub.clone();

    let security_impl = SecurityServiceImpl::new(
        private_key,
        Arc::new(validator),
        Arc::new(CleChiffrageHandlerImpl::new()),
    );

    // Trick for KeyMaster - use own key for encryption. DO NOT DO THIS WITH OTHER DOMAINS.
    security_impl.add_encryption_publickey(encryption_key)?;

    Ok(security_impl)
}


async fn start_threads(
    join_set: &mut JoinSet<()>,
    security: Arc<SecurityServiceImpl>,
    messaging: &MessagingServiceImpl,
    shutdown_token: CancellationToken,
) -> Result<(), CommonError> {

    // Connect to RabbitMQ (throws error on failure).
    // This also spawns all other required threads.
    messaging.start(join_set, shutdown_token.clone()).await?;
    debug!("Started messaging service, connection OK");

    // Spawn other service maintenance threads
    let shutdown_token_clone = shutdown_token.clone();
    join_set.spawn(async move { security.run(shutdown_token_clone).await });

    Ok(())
}
