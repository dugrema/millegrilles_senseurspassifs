use crate::common::*;
use crate::models::{LectureSenseur, SenseurHoraireRow, TransactionLectureHoraire};
use millegrilles_common_rust::bson;
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::epochseconds;
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::mongodb::options::{UpdateOneModel, WriteModel};
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::v3::models::{TransactionOperationAggregator, TransactionWrapper};

pub async fn lectures_transaction_legacy(
    mongo: &dyn MongoDao,
    wrapper: TransactionWrapper,
) -> Result<TransactionOperationAggregator, CommonError> {

    let mut aggregator = TransactionOperationAggregator::new();
    let transaction_value: TransactionLectures = wrapper.message.deserialize()?;
    let transaction_horaire: TransactionLectureHoraire = (&transaction_value).into();
    let row =  SenseurHoraireRow::from(&transaction_horaire);

    // Restoring from backup
    let filtre = doc!{
        CHAMP_USER_ID: &row.user_id,
        CHAMP_UUID_APPAREIL: &row.uuid_appareil,
        "senseur_id": &row.senseur_id,
        "heure": &row.heure
    };
    let collection = mongo.get_collection(COLLECTIONS_SENSEURS_HORAIRE)?;
    let ops = doc! {
        "$setOnInsert": bson::serialize_to_document(&row)?,
    };
    let update_model = WriteModel::UpdateOne(
        UpdateOneModel::builder()
            .upsert(true)
            .namespace(collection.namespace())
            .filter(filtre)
            .update(ops)
            .build()
    );
    // Can use unordered because duplicates are identical entries (ideally would be insert)
    aggregator.unordered = Some(vec![update_model]);

    Ok(aggregator)

    // let most_recent = match transaction_value.plus_recente_lecture() {
    //     Some(inner) => inner,
    //     None => {
    //         debug!("No readings found");
    //         return Ok(aggregator);
    //     }
    // };
    //
    // let senseur = doc! {
    //     "valeur": &most_recent.valeur,
    //     "timestamp": &most_recent.timestamp,
    //     "type": &transaction_value.type_,
    // };
    // let filtre = doc! {
    //     "user_id": &transaction_value.user_id,
    //     CHAMP_UUID_SENSEUR: &transaction_value.uuid_senseur,
    //     "derniere_lecture": &most_recent.timestamp,
    // };
    //             // let filtre = doc! { CHAMP_UUID_SENSEUR: &contenu_transaction.uuid_senseur };
    //             let collection = middleware.get_collection(COLLECTIONS_LECTURES)?;
    //             let ops = doc! {
    //                 "$set": {
    //                     format!("{}.{}", CHAMP_SENSEURS, &contenu_transaction.senseur): senseur,
    //                     "derniere_lecture": &plus_recente_lecture.timestamp,
    //                     "derniere_lecture_dt": &plus_recente_lecture.timestamp,
    //                 },
    //                 "$setOnInsert": {
    //                     CHAMP_CREATION: Utc::now(),
    //                     CHAMP_INSTANCE_ID: &contenu_transaction.instance_id,
    //                     CHAMP_UUID_SENSEUR: &contenu_transaction.uuid_senseur,
    //                     "user_id": &contenu_transaction.user_id,
    //                 },
    //                 "$currentDate": { CHAMP_MODIFICATION: true },
    //             };
    //             // let opts = UpdateOptions::builder().upsert(true).build();
    //             let resultat = match collection
    //                 .update_one(filtre, ops)
    //                 .upsert(true)
    //                 .session(&mut *session)
    //                 .await
    //             {
    //                 Ok(r) => r,
    //                 Err(e) => Err(format!("senseurspassifs.transaction_lectures Erreur traitement transaction senseur : {:?}", e))?
    //             };
    //             debug!("transaction_lectures Resultat : {:?}", resultat);
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TransactionLectures {
    /// Identificateur unique de l'appareil
    uuid_senseur: String,

    /// Identificateur interne du senseur sur l'appareil
    senseur: String,

    /// UUID du noeud MilleGrille
    instance_id: String,

    //// User id (compte)
    user_id: String,

    /// Type de lecture, e.g. temperature, humidite, pression, voltage, batterie, etc.
    #[serde(rename="type")]
    type_: String,

    /// Heure de base des lectures dans la transaction en epoch secs
    #[serde(with="epochseconds")]
    timestamp: DateTime<Utc>,

    /// Moyenne des lectures
    avg: f64,

    /// Valeur max des lectures
    max: f64,

    /// Valeur min des lectures
    min: f64,

    /// Plus vieille date de lecture
    #[serde(with="epochseconds")]
    timestamp_min: DateTime<Utc>,

    /// Plus recente date de lecture
    #[serde(with="epochseconds")]
    timestamp_max: DateTime<Utc>,

    /// Liste des lectures
    lectures: Vec<LectureTransaction>
}

// impl TransactionLectures {
//     fn plus_recente_lecture(&self) -> Option<LectureTransaction> {
//         let mut date_lecture: &DateTime<Utc> = &DateTime::<Utc>::MIN_UTC;
//         let mut lecture = None;
//         for l in &self.lectures {
//             if date_lecture < &l.timestamp {
//                 lecture = Some(l);
//                 date_lecture = &l.timestamp;
//             }
//         }
//         match lecture {
//             Some(l) => Some(l.to_owned()),
//             None => None
//         }
//     }
// }

impl Into<TransactionLectureHoraire> for &TransactionLectures {
    fn into(self) -> TransactionLectureHoraire {
        TransactionLectureHoraire {
            heure: self.timestamp.clone(),
            user_id: self.user_id.clone(),
            uuid_appareil: self.uuid_senseur.clone(),
            senseur_id: self.senseur.clone(),
            lectures: self.lectures.iter().map(|v| v.into()).collect(),
            min: Some(self.min),
            max: Some(self.max),
            avg: Some(self.avg),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LectureTransaction {
    #[serde(with="epochseconds")]
    pub timestamp: DateTime<Utc>,
    pub valeur: f64,
}
 impl Into<LectureSenseur> for &LectureTransaction {
     fn into(self) -> LectureSenseur {
         LectureSenseur {
             timestamp: Default::default(),
             type_: "".to_string(),
             valeur: None,
             valeur_str: None,
         }
     }
 }
