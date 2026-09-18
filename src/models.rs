use std::collections::{BTreeMap, HashMap};
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::{epochseconds, optionepochseconds};
use millegrilles_common_rust::mongo_serde::option_chrono_04_datetime;
use crate::common::{GeopositionAppareil, ParametresDisplay, ProgrammeAppareil};

#[derive(Deserialize)]
pub struct RequestGetUserConfiguration {
    pub user_id: Option<String>
}

#[derive(Deserialize)]
pub struct RowCollectionUsager {
    pub user_id: String,
    pub timezone: Option<String>,
}

#[derive(Serialize)]
pub struct ReponseGetUserConfiguration {
    pub ok: bool,
    pub user_id: String,
    pub timezone: Option<String>,
    pub geoposition: Option<GeopositionDevice>,
}

impl From<RowCollectionUsager> for ReponseGetUserConfiguration {
    fn from(value: RowCollectionUsager) -> Self {
        Self {
            ok: true,
            user_id: value.user_id,
            timezone: value.timezone,
            geoposition: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GeopositionDevice {
    pub latitude: Option<f32>,
    pub longitude: Option<f32>,
    pub accuracy: Option<f32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LectureSenseur {
    #[serde(with="epochseconds")]
    pub timestamp: DateTime<Utc>,
    #[serde(rename="type")]
    pub type_: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valeur: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valeur_str: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfigurationAppareil {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub descriptif: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cacher_senseurs: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub descriptif_senseurs: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub displays: Option<HashMap<String, ParametresDisplay>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub programmes: Option<HashMap<String, ProgrammeAppareil>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geoposition: Option<GeopositionAppareil>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filtres_senseurs: Option<HashMap<String,Vec<String>>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParamsDisplay {
    pub name: String,
    pub format: String,
    pub height: Option<u16>,
    pub width: Option<u16>,
}

#[derive(Serialize)]
pub struct ReponseAppareilUsager {
    pub uuid_appareil: String,
    pub instance_id: Option<String>,
    pub csr_present: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub senseurs: Option<BTreeMap<String, LectureSenseur>>,

    #[serde(default,
        serialize_with = "optionepochseconds::serialize",
        deserialize_with = "opt_chrono_datetime_as_bson_datetime::deserialize")]
    pub derniere_lecture: Option<DateTime<Utc>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub configuration: Option<ConfigurationAppareil>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub displays: Option<Vec<ParamsDisplay>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub programmes: Option<HashMap<String, ProgrammeAppareil>>,

    /// Liste de senseurs avec des lectures disponibles (historique)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub types_donnees: Option<HashMap<String, String>>,

    /// Flag supprime (agit davantage comme "hide")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supprime: Option<bool>,

    /// Flag connecte (websocket)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connecte: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

impl From<DocAppareil> for ReponseAppareilUsager {
    fn from(value: DocAppareil) -> Self {
        Self {
            uuid_appareil: value.uuid_appareil,
            instance_id: value.instance_id,
            csr_present: value.csr.is_some(),
            senseurs: value.senseurs,
            derniere_lecture: value.derniere_lecture,
            configuration: value.configuration,
            displays: value.displays,
            programmes: value.programmes,
            types_donnees: value.types_donnees,
            supprime: value.supprime,
            connecte: value.connecte,
            version: value.version,
        }
    }
}

#[derive(Serialize)]
pub struct ReponseAppareilsUsager {
    pub ok: bool,
    pub appareils: Vec<ReponseAppareilUsager>,
    pub instance_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DocAppareil {
    pub uuid_appareil: String,
    pub instance_id: Option<String>,
    pub user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cle_publique: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub csr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificat: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub senseurs: Option<BTreeMap<String, LectureSenseur>>,
    #[serde(default,
        serialize_with = "optionepochseconds::serialize",
        deserialize_with = "option_chrono_04_datetime::deserialize")]
    pub derniere_lecture: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub configuration: Option<ConfigurationAppareil>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub displays: Option<Vec<ParamsDisplay>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub programmes: Option<HashMap<String, ProgrammeAppareil>>,

    /// Si true, indique qu'une transaction a ete produite (requis pour regeneration)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub persiste: Option<bool>,

    /// Liste de senseurs avec des lectures disponibles (historique)
    // #[serde(skip_serializing_if = "Option::is_none")]
    // pub lectures_disponibles: Option<Vec<String>>,

    /// Liste de senseurs avec des lectures disponibles (historique)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub types_donnees: Option<HashMap<String, String>>,

    /// Flag supprime (agit davantage comme "hide")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supprime: Option<bool>,

    /// Flag connecte (websocket)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connecte: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}
