use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::certificats::VerificateurPermissions;
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::generateur_messages::RoutageMessageAction;
use millegrilles_common_rust::mongo_dao::{MongoDao, MongoDaoTyped};
use millegrilles_common_rust::v3::facades::message_inbound::MessageValidated;
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;
use millegrilles_common_rust::v3::models::{ErrorMessage, TransactionWrapper};
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::{epochseconds, optionepochseconds};
use millegrilles_common_rust::serde_json::json;
use crate::common::*;
use serde;
use crate::flow::transactions::{SenseursPassifsTransactionService, TRANSACTION_MAJ_APPAREIL};
use crate::models::{DocAppareil, TransactionMajAppareil};

pub const COMMANDE_INSCRIRE_APPAREIL: &str = "inscrireAppareil";
pub const COMMANDE_CHALLENGE_APPAREIL: &str = "challengeAppareil";
pub const COMMANDE_SIGNER_APPAREIL: &str = "signerAppareil";
pub const COMMANDE_CONFIRMER_RELAI: &str = "confirmerRelai";
pub const COMMANDE_RESET_CERTIFICATS: &str = "resetCertificatsAppareils";
pub const COMMAND_DISCONNECT_RELAY: &str = "disconnectRelay";

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CommandeConfirmerRelai {
    fingerprint: String,
    #[serde(default, with="optionepochseconds")]
    expiration: Option<DateTime<Utc>>,
}

pub async fn confirm_relai(
    mongo: &dyn MongoDao,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> {
    let commande: CommandeConfirmerRelai = wrapper.message.deserialize()?;

    let certificate = wrapper.certificate.as_ref();
    let common_name = certificate.get_common_name()?;
    let user_id = match certificate.get_user_id()? {
        Some(inner) => inner,
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err("User_id missing from certificate")).await
    };

    let filtre = doc! { "uuid_appareil": &common_name, "user_id": &user_id };
    let ops = doc! {
        "$set": { "fingerprint": &commande.fingerprint },
        "$setOnInsert": {
            "uuid_appareil": common_name,
            "user_id": user_id,
            CHAMP_CREATION: Utc::now()
        },
        "$currentDate": { CHAMP_MODIFICATION: true }
    };

    let collection = mongo.get_collection(COLLECTIONS_RELAIS)?;
    collection
        .update_one(filtre, ops)
        .upsert(true)
        .await?;

    outbound.respond(wrapper.delivery_info, ErrorMessage::ok()).await
}

pub async fn update_device_command<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    transaction: &SenseursPassifsTransactionService,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    let user_id = match wrapper.get_certificate_user_id() {
        Some(user_id) => user_id,
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err("User_id missing from certificate")).await
    };
    // Deserialize, this validates the structure
    let transaction_value: TransactionMajAppareil = wrapper.message.deserialize()?;

    let device_collection = mongo.get_collection_typed::<DocAppareil>(COLLECTIONS_APPAREILS)?;
    let filtre = doc! { CHAMP_UUID_APPAREIL: &transaction_value.uuid_appareil, CHAMP_USER_ID: &user_id };
    if device_collection.find_one(filtre.clone()).await?.is_none() {
        return outbound.respond(wrapper.delivery_info, ErrorMessage::err("Unknown device")).await
    }

    // Run transaction updates
    let delivery_info = wrapper.delivery_info.clone();
    transaction.process_transaction(wrapper.into(), None).await?;

    // Reload updated device
    let device = match device_collection.find_one(filtre.clone()).await? {
        Some(device) => device,
        None => return outbound.respond(delivery_info, ErrorMessage::err("Unknown device after transaction ran")).await
    };

    // Emit events

    // Web update event
    let routing = RoutageMessageAction::builder(
        DOMAINE_NOM,
        TRANSACTION_MAJ_APPAREIL,
        vec![Securite::L2Prive]
    )
        .partition(&user_id)
        .build();
    outbound.emit_event(routing, &device).await?;

    if let Some(configuration) = &device.configuration {
        // Update configuration
        let routing = RoutageMessageAction::builder(
            DOMAINE_NOM,
            EVENEMENT_MAJ_CONFIGURATION_APPAREIL,
            vec![Securite::L2Prive]
        )
            .partition(&user_id)
            .build();
        let configuration_event = json!({
            CHAMP_USER_ID: &user_id,
            CHAMP_UUID_APPAREIL: &transaction_value.uuid_appareil,
            CHAMP_TIMEZONE: configuration.timezone.as_ref(),
        });
        outbound.emit_event(routing, &configuration_event).await?;

        // Update displays
        if let Some(displays) = &configuration.displays {
            let routing = RoutageMessageAction::builder(
                DOMAINE_NOM,
                EVENEMENT_MAJ_DISPLAYS,
                vec![Securite::L2Prive]
            )
                .partition(&user_id)
                .build();
            let displays_event = json!({
                CHAMP_UUID_APPAREIL: &transaction_value.uuid_appareil,
                "displays": displays
            });
            outbound.emit_event(routing, &displays_event).await?;
        }

        // Update programs
        if let Some(programmes) = &configuration.programmes {
            let routing = RoutageMessageAction::builder(
                DOMAINE_NOM,
                EVENEMENT_MAJ_PROGRAMMES,
                vec![Securite::L2Prive]
            )
                .partition(&user_id)
                .build();
            let programs_event = json!({
                CHAMP_UUID_APPAREIL: &transaction_value.uuid_appareil,
                "programmes": programmes
            });
            outbound.emit_event(routing, &programs_event).await?;
        }
    }

    // Respond with complete updated device document
    outbound.respond(delivery_info, device).await
}
