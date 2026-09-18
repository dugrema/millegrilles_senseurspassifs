use millegrilles_common_rust::bson;
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::certificats::VerificateurPermissions;
use millegrilles_common_rust::chrono::{DateTime, Timelike, Utc};
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::{MessageMilleGrillesBufferDefault, MessageMilleGrillesOwned, MessageValidable};
use millegrilles_common_rust::mongo_dao::{MongoDao, MongoDaoTyped};
use millegrilles_common_rust::v3::facades::message_inbound::MessageValidated;
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::generateur_messages::RoutageMessageAction;
use millegrilles_common_rust::tracing::{debug, warn};
use millegrilles_common_rust::v3::PkiService;
use crate::models::{InformationAppareil, LectureAppareil, LectureAppareilInfo, RowRelais};
use crate::constants::*;
use crate::common::*;

pub async fn process_reading_event<M>(
    pki: &dyn PkiService,
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {

    let reading_event: EvenementLecture = wrapper.message.deserialize()?;
    let certificate = wrapper.certificate.as_ref();
    let fingerprint_relai = certificate.fingerprint()?;

    //     // Extraire instance, convertir evenement en LectureAppareilInfo
    let instance_id = reading_event.instance_id.clone();
    let reading_value = reading_event.recuperer_info(pki, mongo, fingerprint_relai.as_str()).await?;

    // Trouver date de la plus recente lecture
    let most_recent_reading = reading_value.calculer_derniere_lecture();

    // Save most recent device value
    update_device_current_value(mongo, instance_id.as_str(), most_recent_reading.as_ref(), &reading_value).await?;

    // Read current state from DB
    let current_state = load_current_state(mongo, &reading_value).await?;

    // Re-send event as confirmed by domain
    send_confirmed_reading(outbound, &current_state).await?;

    // Split readings, save data as volatile (not transaction). This is aggregated once an hour.
    if let Err(e) = add_reading_to_db(mongo, &reading_value).await {
        warn!("Error saving reading : {:?}", e);
    }

    Ok(())
}


#[derive(Clone, Serialize, Deserialize)]
struct EvenementLecture {
    instance_id: String,
    lecture: Option<MessageMilleGrillesOwned>,
    lecture_relayee: Option<LectureAppareilInfo>,
}

impl EvenementLecture {

    async fn recuperer_info(
        self,
        pki: &dyn PkiService,
        mongo: &dyn MongoDao,
        fingerprint_relai: &str
    ) -> Result<LectureAppareilInfo, CommonError> {
        if self.lecture.is_some() {
            // Charger une lecture signee par l'appareil
            self.charger_lecture_directe(pki).await
        } else if self.lecture_relayee.is_some() {
            // Charger une lecture relayee
            self.charger_lecture_relayee(mongo, fingerprint_relai).await
        } else {
            Err(CommonError::Str("lectures.EvenementLecture.recuperer_info Aucun contenu lecture/lecture_relayee"))?
        }
    }

    async fn charger_lecture_directe(
        self,
        pki: &dyn PkiService
    ) -> Result<LectureAppareilInfo, CommonError> {
        let mut lecture = match self.lecture {
            Some(inner) => inner,
            None => Err(CommonError::Str("lectures.EvenementLecture.charger_lecture_directe Field lecture est vide"))?
        };

        lecture.verifier_signature()?;

        // Recuperer le certificat, valider le message.
        let certificat = {
            pki.validate_message(&lecture).await?
        };

        let lecture: LectureAppareil = lecture.deserialize()?;
        let user_id = match certificat.get_user_id()? {
            Some(inner) => inner,
            None => Err(CommonError::Str("lectures.EvenementLecture.charger_lecture_directe Evenement de lecture user_ud manquant du certificat"))?
        };
        let uuid_appareil = match certificat.subject()?.get("commonName") {
            Some(cn) => {
                // Verifier si c'est un role senseurspassifs - pour tous les autres certificats, on ajout le OU.
                match certificat.verifier_roles_string(vec!["senseurspassifs".to_string()])? {
                    true => cn.clone(),
                    false => match certificat.subject()?.get("organizationalUnitName") {
                        Some(ou) => format!("{}_{}", cn, ou),
                        None => cn.to_owned()
                    }
                }
            },
            None => Err(CommonError::Str("lectures.EvenementLecture.charger_lecture_directe Evenement de lecture certificat sans uuid_appareil (commonName)"))?
        };

        Ok(LectureAppareilInfo {
            uuid_appareil,
            user_id,
            lectures_senseurs: lecture.lectures_senseurs,
            displays: lecture.displays,
            notifications: lecture.notifications,
        })
    }

    async fn charger_lecture_relayee(
        self,
        mongo: &dyn MongoDao,
        fingerprint_relai: &str
    ) -> Result<LectureAppareilInfo, CommonError> {
        let lecture = match self.lecture_relayee {
            Some(inner) => inner,
            None => return Err(CommonError::Str("lectures.EvenementLecture.charger_lecture_directe Field lecture est vide"))
        };

        let user_id = lecture.user_id;
        let uuid_appareil = lecture.uuid_appareil;

        // Check that the relay is authorized - just check if row exists
        let filtre = doc! {
            CHAMP_USER_ID: &user_id,
            CHAMP_UUID_APPAREIL: &uuid_appareil,
            "fingerprint": fingerprint_relai
        };
        let collection = mongo.get_collection(COLLECTIONS_RELAIS)?;
        match collection.find_one(filtre).projection(doc!{"_id": true}).await? {
            Some(_inner) => {
                // Ok, autorise
                Ok(LectureAppareilInfo {
                    uuid_appareil,
                    user_id,
                    lectures_senseurs: lecture.lectures_senseurs,
                    displays: lecture.displays,
                    notifications: lecture.notifications,
                })
            },
            None => {
                // Il n'y a pas d'autorisation
                Err(CommonError::String(format!(
                    "charger_lecture_relayee Relai {} non autorise pour appareil {}",
                    fingerprint_relai,
                    uuid_appareil
                )))
            }
        }
    }
}

async fn update_device_current_value(
    mongo: &dyn MongoDao,
    instance_id: &str,
    most_recent_reading: Option<&DateTime<Utc>>,
    reading: &LectureAppareilInfo
) -> Result<(), CommonError> {
    let filtre = doc! {
        CHAMP_UUID_APPAREIL: &reading.uuid_appareil,
        "user_id": reading.user_id.as_str(),
    };

    let mut set_ops = doc! {
        CHAMP_INSTANCE_ID: &instance_id,
        "connecte": true,
        // TODO - fix date duplication
        "derniere_lecture": most_recent_reading,
        "derniere_lecture_dt": most_recent_reading,
    };
    for (senseur_id, lecture_senseur) in &reading.lectures_senseurs {
        set_ops.insert(format!("senseurs.{}", senseur_id), bson::serialize_to_document(&lecture_senseur)?);
    }
    if let Some(displays) = &reading.displays {
        let displays_bson: Vec<bson::Document> = displays
            .iter()
            .map(|v| bson::serialize_to_document(v).expect("bson"))
            .collect();
        debug!("Conserver displays : {:?}", displays);
        set_ops.insert("displays", displays_bson);
    }

    let ops = doc! {
        "$set": set_ops,
        "$setOnInsert": {
            CHAMP_CREATION: Utc::now(),
            CHAMP_UUID_APPAREIL: &reading.uuid_appareil,
            "user_id": reading.user_id.as_str(),
        },
        "$currentDate": { CHAMP_MODIFICATION: true },
    };
    let collection = mongo.get_collection(COLLECTIONS_APPAREILS)?;
    let resultat_update = collection.update_one(filtre, ops).upsert(true).await?;
    debug!("evenement_domaine_lecture Resultat update : {:?}", resultat_update);

    Ok(())
}

async fn load_current_state<M>(
    mongo: &M,
    reading: &LectureAppareilInfo,
) -> Result<InformationAppareil, CommonError> where M: MongoDaoTyped {
    let projection = doc! {
        CHAMP_UUID_APPAREIL: 1,
        CHAMP_USER_ID: 1,
        CHAMP_INSTANCE_ID: 1,
        "derniere_lecture": 1,
        CHAMP_SENSEURS: 1,
        "descriptif": 1,
    };
    let filtre = doc! { CHAMP_UUID_APPAREIL: &reading.uuid_appareil, CHAMP_USER_ID: &reading.user_id };
    let collection = mongo.get_collection_typed::<InformationAppareil>(COLLECTIONS_APPAREILS)?;
    match collection.find_one(filtre).projection(projection).await? {
        Some(inner) => Ok(inner),
        None => Err(CommonError::String(format!("Unkown device id {} for user_id {}", reading.uuid_appareil, reading.user_id)))
    }
}

async fn send_confirmed_reading(outbound: &MessageOutboundFacade, reading: &InformationAppareil) -> Result<(), CommonError> {
    let routing = RoutageMessageAction::builder(
        DOMAINE_NOM,
        EVENEMENT_LECTURE_CONFIRMEE,
        vec![Securite::L2Prive]
    )
        .partition(reading.user_id.as_str())
        .build();

    if let Err(e) = outbound.emit_event(routing, reading).await {
        warn!("Error emitting confirmed reading event: {:?}", e)
    }

    Ok(())
}

async fn add_reading_to_db(mongo: &dyn MongoDao, reading: &LectureAppareilInfo) -> Result<(), CommonError> {
    let collection = mongo.get_collection(COLLECTIONS_LECTURES)?;

    for (device_id, value) in &reading.lectures_senseurs {
        let hour = heure_juste(&value.timestamp);
        let filtre = doc!{
            CHAMP_UUID_APPAREIL: &reading.uuid_appareil,
            "senseur_id": &device_id,
            "user_id": reading.user_id.as_str(),
            "heure": &hour,
        };
        let now = Utc::now();
        let set_on_insert = doc! {
            CHAMP_CREATION: &now,
            CHAMP_UUID_APPAREIL: &reading.uuid_appareil,
            "senseur_id": device_id,
            "user_id": reading.user_id.as_str(),
            "heure": hour,
        };
        let ops = doc! {
            "$push": {
                "lectures": bson::serialize_to_document(&value)?,
            },
            "$setOnInsert": set_on_insert,
            "$currentDate": {CHAMP_MODIFICATION: true},
        };
        let _ = collection.update_one(filtre, ops).upsert(true).await?;
    }

    Ok(())
}

fn heure_juste(date: &DateTime<Utc>) -> DateTime<Utc> {
    date.with_minute(0).expect("with_minutes")
        .with_second(0).expect("with_seconds")
        .with_nanosecond(0).expect("with_nanosecond")
}
