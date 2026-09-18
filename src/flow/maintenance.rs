use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::chrono::{Duration, Utc};
use millegrilles_common_rust::generateur_messages::RoutageMessageAction;
use millegrilles_common_rust::mongo_dao::MongoDaoTyped;
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;
use millegrilles_common_rust::constantes::*;
use crate::common::{COLLECTIONS_APPAREILS, DOMAINE_NOM};
use crate::models::{DocAppareil, EvenementPresenceAppareilUser};

pub async fn mark_devices_offline<M>(mongo: &M, outbound: &MessageOutboundFacade) -> Result<(), CommonError> where M: MongoDaoTyped {
    let expired = Utc::now() - Duration::minutes(1);

    let filtre = doc! {
        "connecte": true,
        "derniere_lecture": {"$lte": expired},
    };

    let collection = mongo.get_collection_typed::<DocAppareil>(COLLECTIONS_APPAREILS)?;
    let mut cursor = collection.find(filtre.clone()).await?;
    while cursor.advance().await? {
        let device = cursor.deserialize_current()?;
        // Emit event for device
        {
            if let Some(user_id) = device.user_id {
                let evenement_reemis = EvenementPresenceAppareilUser {
                    uuid_appareil: device.uuid_appareil,
                    user_id,
                    version: device.version,
                    connecte: false
                };
                let routage = RoutageMessageAction::builder(
                    DOMAINE_NOM, "\
                    presenceAppareil",
                    vec![Securite::L2Prive]
                )
                    .partition(&evenement_reemis.user_id)
                    .build();
                outbound.emit_event(routage, &evenement_reemis).await?;
            }
        }
    }

    let ops = doc! {
        "$unset": {"instance_id": true},
        "$set": {"connecte": false},
        "$currentDate": {CHAMP_MODIFICATION: true},
    };
    collection.update_many(filtre, ops).await?;

    Ok(())
}
