use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::chrono;
use millegrilles_common_rust::chrono::Utc;
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::error::Error;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::mongo_dao::MongoDao;

use crate::common::{DocAppareil, COLLECTIONS_APPAREILS, DOMAINE_NOM};
use crate::evenements::EvenementPresenceAppareilUser;

pub async fn mark_devices_offline<M>(middleware: &M) -> Result<(), Error>
where M: GenerateurMessages + MongoDao
{
    let expired = Utc::now() - chrono::Duration::minutes(5);

    let filtre = doc! {
        "connecte": true,
        "derniere_lecture": {"$lte": expired},
    };

    let collection = middleware.get_collection_typed::<DocAppareil>(COLLECTIONS_APPAREILS)?;
    let mut cursor = collection.find(filtre.clone(), None).await?;
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
                let routage = RoutageMessageAction::builder(DOMAINE_NOM, "presenceAppareil", vec![Securite::L2Prive])
                    .partition(&evenement_reemis.user_id)
                    .build();
                middleware.emettre_evenement(routage, &evenement_reemis).await?;
            }
        }
    }

    let ops = doc! {
        "$unset": {"instance_id": true},
        "$set": {"connecte": false},
        "$currentDate": {CHAMP_MODIFICATION: true},
    };
    collection.update_many(filtre, ops, None).await?;

    Ok(())
}
