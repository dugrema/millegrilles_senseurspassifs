use millegrilles_common_rust::serde::{Deserialize, Serialize};

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
