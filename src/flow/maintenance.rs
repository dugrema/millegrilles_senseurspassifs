use crate::common::{COLLECTIONS_APPAREILS, DOMAINE_NOM};
use crate::flow::readings::generate_readings_for_transactions;
use crate::flow::transactions::SenseursPassifsTransactionService;
use crate::models::{DocAppareil, EvenementPresenceAppareilUser};
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::certificats::VerificateurPermissions;
use millegrilles_common_rust::chrono::{Datelike, Duration, Timelike, Utc};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::generateur_messages::RoutageMessageAction;
use millegrilles_common_rust::messages_generiques::MessageCedule;
use millegrilles_common_rust::mongo_dao::MongoDaoTyped;
use millegrilles_common_rust::tracing::{debug, error, warn};
use millegrilles_common_rust::v3::PresenceService;
use millegrilles_common_rust::v3::facades::message_inbound::MessageValidated;
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;


pub async fn process_ticker_job<M>(
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
    let _day = trigger_value.get_date().weekday();

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

async fn mark_devices_offline<M>(mongo: &M, outbound: &MessageOutboundFacade) -> Result<(), CommonError> where M: MongoDaoTyped {
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
