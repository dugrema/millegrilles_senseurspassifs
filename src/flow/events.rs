use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::tracing::warn;
use millegrilles_common_rust::v3::facades::message_inbound::MessageValidated;
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;

pub const EVENEMENT_PRESENCE_APPAREIL: &str = "presenceAppareil";

pub async fn device_presence_event(
    mongo: &dyn MongoDao,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> {
    warn!("Implement device_presence_event");  // TODO
    Ok(())
}

