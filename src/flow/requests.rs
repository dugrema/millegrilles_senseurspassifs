use crate::common::*;
use crate::models::{DocAppareil, GeopositionAppareil, InformationAppareil, ReponseAppareilUsager, ReponseAppareilsUsager, ReponseGetUserConfiguration, RequestGetUserConfiguration, RowCollectionUsager};
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::certificats::VerificateurPermissions;
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::mongo_dao::MongoDaoTyped;
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::tracing::info;
use millegrilles_common_rust::v3::facades::message_inbound::MessageValidated;
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;
use millegrilles_common_rust::v3::models::ErrorMessage;

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

pub async fn process_request<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated
) -> Result<(), CommonError> where M: MongoDaoTyped {
    let action = match wrapper.get_routing_action() {
        Some(action) => action,
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err("No action provided in request")).await
    };
    match action {
        REQUETE_GET_APPAREILS_USAGER => get_user_devices(mongo, outbound, wrapper).await,
        REQUETE_LISTE_NOEUDS => todo!(),
        REQUETE_GET_NOEUD => todo!(),
        REQUETE_LISTE_SENSEURS_PAR_UUID => todo!(),
        REQUETE_LISTE_SENSEURS_NOEUD => todo!(),
        REQUETE_GET_APPAREILS_EN_ATTENTE => todo!(),
        REQUETE_GET_APPAREIL_DISPLAY_CONFIGURATION => get_device_display_configuration(mongo, outbound, wrapper).await,
        REQUETE_GET_APPAREIL_PROGRAMMES_CONFIGURATION => get_device_program_configuration(mongo, outbound, wrapper).await,
        REQUETE_GET_CONFIGURATION_USAGER => get_user_configuration(mongo, outbound, wrapper).await,
        _ => {
            info!("Unknown action {} for process_request, skipping", action);
            Ok(())
        }
    }
}

pub async fn process_device_request<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated
) -> Result<(), CommonError> where M: MongoDaoTyped {
    let action = match wrapper.get_routing_action() {
        Some(action) => action,
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err("No action provided in request")).await
    };
    match action {
        REQUETE_GET_TIMEZONE_APPAREIL => get_device_timezone(mongo, outbound, wrapper).await,
        _ => {
            info!("Unknown action {} for process_request, skipping", action);
            Ok(())
        }
    }
}

async fn get_user_devices<M>(
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
                info!("Mapping error to DocAppareil for user_id {}: {:?}", user_id, e);
                continue
            }
        };

        devices.push(ReponseAppareilUsager::from(value));
    }


    let response = ReponseAppareilsUsager {ok: true, appareils: devices, instance_id};
    outbound.respond(wrapper.delivery_info, response).await
}

async fn get_user_configuration<M>(
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

#[derive(Deserialize)]
struct RequeteGetTimezoneAppareil {
    user_id: String,
    uuid_appareil: String
}

#[derive(Serialize)]
struct ReponseGetTimezoneAppareil {
    ok: bool,
    err: Option<String>,
    timezone: Option<String>,
    geoposition: Option<GeopositionAppareil>,
}

async fn get_device_timezone<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated
) -> Result<(), CommonError> where M: MongoDaoTyped {

    let request: RequeteGetTimezoneAppareil = wrapper.message.deserialize()?;

    let device_collection = mongo.get_collection_typed::<InformationAppareil>(COLLECTIONS_APPAREILS)?;
    let filtre = doc! {CHAMP_USER_ID: &request.user_id, CHAMP_UUID_APPAREIL: &request.uuid_appareil};
    let device_info = match device_collection.find_one(filtre).await? {
        Some(device_info) => device_info,
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err("Unknown device for user")).await
    };

    // Locate device timezone
    let (timezone, geoposition) = match device_info.configuration {
        Some(configuration) => (configuration.timezone, configuration.geoposition),
        None => (None, None)
    };
    let timezone = match timezone {
        Some(inner) => Some(inner),
        None => {
            // Tenter de charger la timezone du compte usager
            let collection = mongo.get_collection_typed::<RowCollectionUsager>(COLLECTIONS_USAGER)?;
            let filtre = doc! { CHAMP_USER_ID: &request.user_id };
            match collection.find_one(filtre).await? {
                Some(inner) => inner.timezone,
                None => None
            }
        }
    };

    outbound.respond(wrapper.delivery_info, ReponseGetTimezoneAppareil {
        ok: true,
        err: None,
        timezone,
        geoposition
    }).await
}

#[derive(Serialize)]
struct ResponseGetDeviceDisplayConfiguration {
    ok: bool,
    display_configuration: DocAppareil,
}

async fn get_device_display_configuration<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated
) -> Result<(), CommonError> where M: MongoDaoTyped {
    // Extract user_id, uuid_appareil (common name) from certificate
    let user_id = match wrapper.certificate.get_user_id()? {
        Some(u) => u.to_owned(),
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err("Missing user_id from certificate")).await
    };
    let uuid_appareil = match wrapper.certificate.subject()?.get("commonName") {
        Some(s) => s.to_owned(),
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err("Missing common name from certificate")).await
    };

    let filtre = doc! { CHAMP_USER_ID: user_id, CHAMP_UUID_APPAREIL: uuid_appareil };
    let projection = doc! {
        CHAMP_UUID_APPAREIL: 1,
        CHAMP_INSTANCE_ID: 1,
        "derniere_lecture": 1,
        "configuration.displays": 1,
        "configuration.descriptif": 1,
    };
    let collection = mongo.get_collection_typed::<DocAppareil>(COLLECTIONS_APPAREILS)?;
    let document_configuration = collection.find_one(filtre).projection(projection).await?;

    match document_configuration {
        Some(value) => {
            outbound.respond(wrapper.delivery_info, ResponseGetDeviceDisplayConfiguration {
                ok: true,
                display_configuration: value
            }).await
        },
        None => {
            outbound.respond(wrapper.delivery_info, ErrorMessage::err("Device not found")).await
        }
    }
}

#[derive(Serialize)]
struct ResponseGetDeviceProgramConfiguration {
    ok: bool,
    programmes: DocAppareil,
}
async fn get_device_program_configuration<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated
) -> Result<(), CommonError> where M: MongoDaoTyped {
    // Extract user_id, uuid_appareil (common name) from certificate
    let user_id = match wrapper.certificate.get_user_id()? {
        Some(u) => u.to_owned(),
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err("Missing user_id from certificate")).await
    };
    let uuid_appareil = match wrapper.certificate.subject()?.get("commonName") {
        Some(s) => s.to_owned(),
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err("Missing common name from certificate")).await
    };

    let filtre = doc! { CHAMP_USER_ID: user_id, CHAMP_UUID_APPAREIL: uuid_appareil };
    let projection = doc! {
        CHAMP_UUID_APPAREIL: 1,
        CHAMP_INSTANCE_ID: 1,
        "derniere_lecture": 1,
        "configuration.programmes": 1,
    };
    let collection = mongo.get_collection_typed::<DocAppareil>(COLLECTIONS_APPAREILS)?;
    let document_configuration = collection.find_one(filtre).projection(projection).await?;

    match document_configuration {
        Some(value) => {
            outbound.respond(wrapper.delivery_info, ResponseGetDeviceProgramConfiguration {
                ok: true,
                programmes: value
            }).await
        },
        None => {
            outbound.respond(wrapper.delivery_info, ErrorMessage::err("Device not found")).await
        }
    }
}
