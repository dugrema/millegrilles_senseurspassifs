use chrono_tz::Tz;
use millegrilles_common_rust::bson::{doc, Document};
use millegrilles_common_rust::certificats::VerificateurPermissions;
use millegrilles_common_rust::chrono::{DateTime, Duration, Timelike, Utc};
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::mongo_dao::{MongoDao, MongoDaoTyped};
use millegrilles_common_rust::tracing::{debug, info};
use millegrilles_common_rust::v3::facades::message_inbound::MessageValidated;
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;
use millegrilles_common_rust::v3::models::ErrorMessage;
use millegrilles_common_rust::{bson, serde};
use millegrilles_common_rust::tokio_stream::StreamExt;
use serde::{Deserialize, Serialize};
use crate::common::COLLECTIONS_SENSEURS_HORAIRE;
use crate::models::{RequeteGetStatistiquesSenseur, ResultatStatistiquesSenseurRow};

pub async fn send_device_report(
    mongo: &dyn MongoDao,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated
) -> Result<(), CommonError> {

    let request: RequeteGetStatistiquesSenseur = wrapper.message.deserialize()?;

    let user_id = match wrapper.certificate.get_user_id()? {
        Some(inner) => inner,
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err("missing user_id")).await
    };

    // Determine timezone
    const UTC_STR: &str = "UTC";
    let tz: Tz = match request.timezone.as_ref() {
        Some(tz) => {
            tz.parse().unwrap_or_else(|e| {
                info!("send_device_report Bad timezone, defaulting a UTC : {:?}", e);
                UTC_STR.parse().expect("utc")
            })
        },
        None => UTC_STR.parse().expect("utc")
    };
    debug!("send_device_report Timezone {:?} - grouping {:?}", tz, request.custom_grouping);

    let result = match request.custom_grouping.as_ref() {
        Some(_) => {
            report_custom_grouping(mongo, user_id.as_str(), &request, &tz).await?
        },
        None => {
            report_default_groupings(mongo, user_id.as_str(), &request, &tz).await?
        }
    };

    outbound.respond(wrapper.delivery_info, result).await
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DeviceReportResponseDefaults {
    ok: bool,
    #[serde(rename="periode72h", skip_serializing_if = "Option::is_none")]
    period_72h: Option<Vec<ResultatStatistiquesSenseurRow>>,
    #[serde(rename="periode31j", skip_serializing_if = "Option::is_none")]
    period_31d: Option<Vec<ResultatStatistiquesSenseurRow>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    custom: Option<Vec<ResultatStatistiquesSenseurRow>>,
}

async fn report_default_groupings(
    mongo: &dyn MongoDao,
    user_id: &str,
    request: &RequeteGetStatistiquesSenseur,
    tz: &Tz,
) -> Result<DeviceReportResponseDefaults, CommonError> {

    let period_72h = {
        let min_date = Utc::now() - Duration::days(3);
        query_aggregate(mongo, user_id, &request, "heures", &tz, min_date, None).await?
    };

    let period_31d = {
        let min_date = Utc::now() - Duration::days(31);
        let min_date = jour_juste(&min_date);
        query_aggregate(mongo, user_id, &request, "jours", &tz, min_date, None).await?
    };

    Ok(DeviceReportResponseDefaults { ok: true, period_72h: Some(period_72h), period_31d: Some(period_31d), custom: None })
}

async fn report_custom_grouping(
    mongo: &dyn MongoDao,
    user_id: &str,
    request: &RequeteGetStatistiquesSenseur,
    tz: &Tz,
) -> Result<DeviceReportResponseDefaults, CommonError> {
    let grouping = match request.custom_grouping.as_ref() {
        Some(grouping) => grouping,
        None => return Err(CommonError::Str("Grouping missing")),
    };
    let min_date = match request.custom_intervalle_min {
        Some(d) => d,
        None => Err(format!("rapport_custom custom_intervalle_min manquant"))?
    };
    let min_date: DateTime<Utc> = DateTime::from_timestamp(min_date as i64, 0).expect("timestamp null");
    let max_date = match request.custom_intervalle_max {
        Some(inner) => {
            Some(DateTime::from_timestamp(inner as i64, 0).expect("timestamp null"))
        },
        None => None
    };

    let report = query_aggregate(
        mongo,
        user_id,
        request,
        grouping.as_str(),
        tz,
        min_date,
        max_date
    ).await?;

    Ok(DeviceReportResponseDefaults { ok: true, period_72h: None, period_31d: None, custom: Some(report) })
}

async fn query_aggregate(
    mongo: &dyn MongoDao,
    user_id: &str,
    requete: &RequeteGetStatistiquesSenseur,
    grouping: &str,
    tz: &Tz,
    min_date: DateTime<Utc>,
    max_date: Option<DateTime<Utc>>
) -> Result<Vec<ResultatStatistiquesSenseurRow>, CommonError>
{
    debug!("Rapport Custom sur grouping {}", grouping);

    let mut intervalle_heures = doc! {"$gte": min_date};
    if let Some(inner) = max_date {
        intervalle_heures.insert("$lt", inner);
    }

    let filtre = doc! {
        "user_id": user_id,
        "uuid_appareil": &requete.uuid_appareil,
        "senseur_id": &requete.senseur_id,
        "heure": intervalle_heures,
    };

    let pipeline = match grouping {
        "heures" => pipeline_heure(filtre),
        "jours" => pipeline_jour(filtre, tz),
        _ => Err(format!("Type grouping {} non supporte", grouping))?
    };

    // debug!("query_aggregate Requete pipeline\n{}", serde_json::to_string_pretty(&pipeline)?);

    let mut reponse = Vec::with_capacity(100);
    let collection = mongo.get_collection(COLLECTIONS_SENSEURS_HORAIRE)?;
    let mut result = collection.aggregate(pipeline).await?;
    while let Some(d) = result.next().await {
        let row: ResultatStatistiquesSenseurRow = bson::deserialize_from_document(d?)?;
        reponse.push(row);
    }

    Ok(reponse)
}

fn pipeline_heure(filtre: Document) -> Vec<Document> {
    vec![
        doc! { "$match": filtre },
        doc! { "$project": {"heure": 1, "avg": 1, "min": 1, "max": 1} },
        doc! { "$sort": {"heure": 1} }
    ]
}

fn pipeline_jour(filtre: Document, tz: &Tz) -> Vec<Document> {
    vec![
        doc! { "$match": filtre },
        doc! { "$project": {"heure": 1, "avg": 1, "min": 1, "max": 1} },
        doc! { "$group": {
            // "_id": { "$dateToString": { "format": "%Y-%m-%d", "date": {"$toDate": {"$multiply": ["$heure", 1000]}}, "timezone": tz.to_string() } },
            "_id": { "$dateToString": { "format": "%Y-%m-%d", "date": "$heure", "timezone": tz.to_string() } },
            "heure": {"$min": "$heure"},
            "avg": {"$avg": "$avg"},
            "min": {"$min": "$min"},
            "max": {"$max": "$max"},
        } },
        doc! { "$sort": {"heure": 1} }
    ]
}

fn jour_juste(date: &DateTime<Utc>) -> DateTime<Utc> {
    date.with_hour(0).expect("with_minutes")
        .with_minute(0).expect("with_minutes")
        .with_second(0).expect("with_seconds")
        .with_nanosecond(0).expect("with_nanosecond")
}
