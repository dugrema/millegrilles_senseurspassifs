use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::certificats::VerificateurPermissions;
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::v3::facades::message_inbound::MessageValidated;
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;
use millegrilles_common_rust::v3::models::ErrorMessage;
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::{epochseconds, optionepochseconds};
use crate::common::*;
use serde;

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
