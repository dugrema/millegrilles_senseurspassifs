use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::mongo_dao::MongoDaoTyped;
use millegrilles_common_rust::tracing::warn;
use millegrilles_common_rust::v3::facades::message_inbound::MessageValidated;
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;

pub async fn process_reading_event<M>(
    mongo: &M,
    _outbound: &MessageOutboundFacade,
    _wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    warn!("TODO");
    Ok(())
}
