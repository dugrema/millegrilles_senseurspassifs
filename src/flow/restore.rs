use crate::common::*;
use crate::common::{COLLECTIONS_APPAREILS, COLLECTIONS_SENSEURS_HORAIRE};
use crate::flow::app_service::ApplicationService;
use crate::models::SenseurHoraireRow;
use millegrilles_common_rust::bson;
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::bson::serde_helpers::datetime::FromChrono04DateTime;
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::mongo_dao::MongoDaoTyped;
use millegrilles_common_rust::openssl::pkey::{PKey, Private};
use millegrilles_common_rust::tokio::time::sleep;
use millegrilles_common_rust::tokio_util::sync::CancellationToken;
use millegrilles_common_rust::tracing::{debug, error, info};
use serde::Deserialize;
use std::sync::Arc;

pub async fn restore_from_backup(
    app_service: Arc<ApplicationService>,
    master_key: &PKey<Private>,
    shutdown_token: CancellationToken
) {
    let return_code = match restore(app_service.as_ref(), master_key, true).await {
        Ok(()) => {
            info!("Restoration process complete - shutting down");
            0
        },
        Err(e) => {
            error!("Error during restoration: {:?}", e);
            shutdown_token.cancel();
            2
        }
    };

    // Stop all processes - restoration complete
    shutdown_token.cancel();

    sleep(std::time::Duration::from_secs(2)).await;
    std::process::exit(return_code);
}

async fn restore(
    app_service: &ApplicationService,
    master_key: &PKey<Private>,
    resume: bool
) -> Result<(), CommonError> {
    info!("Beginning database restoration");
    let result = app_service.restore(
        Some(&master_key),
        resume,
        None,
    ).await?;

    // Produce final restoration report
    info!(
        "Transactions processed {} transactions ({} skipped then {} resumed)",
        result.transaction_count,
        result.initially_skipped,
        result.transaction_count - result.initially_skipped,
    );

    Ok(())
}

#[derive(Debug, Deserialize)]
struct DeviceHourAggregateId {
    user_id: String,
    uuid_appareil: String,
    senseur_id: String,
}

#[derive(Debug, Deserialize)]
struct DeviceHourAggregateRow {
    _id: DeviceHourAggregateId,
    #[serde(with="FromChrono04DateTime")]
    heure: DateTime<Utc>,
}

/// This rebuilds devices using the most recent reading for each sensor.
pub async fn rebuild_devices<M>(mongo: &M) -> Result<(), CommonError> where M: MongoDaoTyped {
    let collection_appareils = mongo.get_collection(COLLECTIONS_APPAREILS)?;
    let collection_senseurs_horaire = mongo.get_collection_typed::<SenseurHoraireRow>(COLLECTIONS_SENSEURS_HORAIRE)?;

    let pipeline = vec![
        doc! { "$project": {CHAMP_USER_ID: 1, CHAMP_UUID_APPAREIL: 1, "senseur_id": 1, "heure": 1} },
        doc! { "$group": {
            "_id": { CHAMP_USER_ID: "$user_id", CHAMP_UUID_APPAREIL: "$uuid_appareil", "senseur_id": "$senseur_id" },
            "heure": {"$max": "$heure"},
        } }
    ];
    debug!("rebuild_sensor_list Pipeline {:?}", pipeline);
    let mut cursor = collection_senseurs_horaire.aggregate(pipeline).await?;

    while cursor.advance().await? {
        let row: DeviceHourAggregateRow = bson::deserialize_from_document(cursor.deserialize_current()?)?;
        debug!("rebuild_sensor_list Loading values for {:?}", row);
        let filtre_row = doc!{
            CHAMP_USER_ID: &row._id.user_id,
            CHAMP_UUID_APPAREIL: &row._id.uuid_appareil,
            "senseur_id": &row._id.senseur_id,
            "heure": &row.heure,
        };
        let lecture = collection_senseurs_horaire.find_one(filtre_row).await?;
        if let Some(lecture) = lecture {
            debug!("rebuild_sensor_list Lecture loaded: {:?}", lecture);
            let value = match lecture.avg {
                Some(value) => doc!{
                    "timestamp": lecture.heure.timestamp(),
                    "type": lecture.type_,
                    "valeur": value,
                },
                None => doc!{
                    "timestamp": lecture.heure.timestamp(),
                    "type": lecture.type_,
                }
            };

            let filtre = doc!{CHAMP_USER_ID: lecture.user_id, CHAMP_UUID_APPAREIL: lecture.uuid_appareil};
            let ops = doc!{
                "$set": { format!{"senseurs.{}", lecture.senseur_id}: value },
                "$currentDate": { CHAMP_MODIFICATION: true }
            };

            debug!("rebuild_sensor_list Row filtre: {:?} ops {:?}", filtre, ops);

            collection_appareils.update_one(filtre, ops).await?;
        } else {
            info!("rebuild_sensor_list No match for {:?}", row);
        }
    }

    Ok(())
}
