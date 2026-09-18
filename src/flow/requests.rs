use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::certificats::VerificateurPermissions;
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::mongo_dao::{MongoDaoImpl, MongoDaoTyped};
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::tracing::info;
use millegrilles_common_rust::v3::facades::message_inbound::MessageValidated;
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;
use millegrilles_common_rust::v3::models::ErrorMessage;
use crate::common::*;
use crate::models::{DocAppareil, ReponseAppareilUsager, ReponseAppareilsUsager, ReponseGetUserConfiguration, RequestGetUserConfiguration, RowCollectionUsager};

pub const REQUETE_GET_APPAREILS_USAGER: &str = "getAppareilsUsager";
pub const REQUETE_LISTE_NOEUDS: &str = "listeNoeuds";
pub const REQUETE_GET_NOEUD: &str = "getNoeud";
pub const REQUETE_LISTE_SENSEURS_PAR_UUID: &str = "listeSenseursParUuid";
pub const REQUETE_LISTE_SENSEURS_NOEUD: &str = "listeSenseursPourNoeud";
pub const REQUETE_GET_APPAREILS_EN_ATTENTE: &str = "getAppareilsEnAttente";
pub const REQUETE_GET_APPAREIL_DISPLAY_CONFIGURATION: &str = "getAppareilDisplayConfiguration";
pub const REQUETE_GET_APPAREIL_PROGRAMMES_CONFIGURATION: &str = "getAppareilProgrammesConfiguration";
pub const REQUETE_GET_STATISTIQUES_SENSEUR: &str = "getStatistiquesSenseur";
pub const REQUETE_GET_CONFIGURATION_USAGER: &str = "getConfigurationUsager";
pub const REQUETE_GET_TIMEZONE_APPAREIL: &str = "getTimezoneAppareil";

pub async fn get_user_devices<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated
) -> Result<(), CommonError> where M: MongoDaoTyped {
    let user_id = match wrapper.certificate.get_user_id()? {
        Some(inner) => inner,
        None => {
            return outbound.respond(wrapper.delivery_info, ErrorMessage::err("Missing user_id from certificate")).await
        }
    };
    let instance_id = wrapper.certificate.get_common_name()?;

    let filtre = doc! { CHAMP_USER_ID: &user_id };

    let projection = doc! {
        CHAMP_UUID_APPAREIL: 1,
        CHAMP_INSTANCE_ID: 1,
        "derniere_lecture": 1,
        "descriptif": 1,
        "senseurs": 1,
        "configuration": 1,
        "displays": 1,
        "programmes": 1,
        "types_donnees": 1,
        "supprime": 1,
        CHAMP_CONNECTE: 1,
        CHAMP_VERSION: 1,
        "csr": 1,
    };

    let collection = mongo.get_collection_typed::<DocAppareil>(COLLECTIONS_APPAREILS)?;
    let mut cursor = collection.find(filtre).limit(100).projection(projection).await?;

    let mut devices = Vec::new();
    while let Some(row) = cursor.next().await {
        let value = match row {
            Ok(row) => row,
            Err(e) => {
                info!("Mapping error to DocAppareil for user_id {}", user_id);
                continue
            }
        };

        devices.push(ReponseAppareilUsager::from(value));
    }


    let response = ReponseAppareilsUsager {ok: true, appareils: devices, instance_id};
    outbound.respond(wrapper.delivery_info, response).await
}

pub async fn get_user_configuration<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated
) -> Result<(), CommonError> where M: MongoDaoTyped {

    let request: RequestGetUserConfiguration = wrapper.message.deserialize()?;

    let user_id = match wrapper.certificate.get_user_id()? {
        Some(inner) => inner,
        None => {
            if ! wrapper.certificate.verifier_exchanges(vec![Securite::L2Prive])? {
                return outbound.respond(wrapper.delivery_info, ErrorMessage::err("Missing user_id from certificate")).await
            }
            match request.user_id {
                Some(inner) => inner,
                None => {
                    return outbound.respond(wrapper.delivery_info, ErrorMessage::err("Missing user_id from request")).await
                }
            }
        }
    };

    let collection = mongo.get_collection_typed::<RowCollectionUsager>(COLLECTIONS_USAGER)?;
    let user_info = collection.find_one(doc!{ CHAMP_USER_ID: &user_id }).await?;

    match user_info {
        Some(user_info) => {
            // Respond
            outbound.respond(wrapper.delivery_info,ReponseGetUserConfiguration::from(user_info)).await
        },
        None => {
            outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(404, "Unknown user_id")).await
        }
    }
}
