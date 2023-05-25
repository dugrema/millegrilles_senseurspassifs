use std::cmp::max;
use std::collections::HashMap;
use std::error::Error;
use std::time::Duration;
use log::{debug, error, warn};
use millegrilles_common_rust::bson::{DateTime as BsonDateTime, doc};
use millegrilles_common_rust::certificats::ValidateurX509;
use millegrilles_common_rust::{chrono, serde_json};
use millegrilles_common_rust::chrono::{DateTime, NaiveDateTime, Timelike, Utc};
use millegrilles_common_rust::constantes::Securite;
use millegrilles_common_rust::formatteur_messages::{DateEpochSeconds, MessageMilleGrille, MessageSerialise};
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, convertir_to_bson, convertir_to_bson_array, convertir_value_mongodate, MongoDao};
use millegrilles_common_rust::mongodb::options::{FindOneOptions, FindOptions, Hint, UpdateOptions};
use millegrilles_common_rust::recepteur_messages::MessageValideAction;
use millegrilles_common_rust::verificateur::VerificateurMessage;
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::serde_json::Value;
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::math::{arrondir, compter_fract_digits};

use crate::common::*;
use crate::senseurspassifs::GestionnaireSenseursPassifs;

struct LectureAppareilInfo {
    uuid_appareil: String,
    user_id: String,
    lectures_senseurs: HashMap<String, LectureSenseur>,
    displays: Option<Vec<ParamsDisplay>>,
}

impl LectureAppareilInfo {

    fn calculer_derniere_lecture(&self) -> Option<DateEpochSeconds> {
        let mut date_lecture: &chrono::DateTime<Utc> = &chrono::MIN_DATETIME;
        for l in self.lectures_senseurs.values() {
            date_lecture = &l.timestamp.get_datetime().max(date_lecture);
        }

        match date_lecture == &chrono::MIN_DATETIME {
            true => {
                None
            },
            false => {
                Some(DateEpochSeconds::from(date_lecture.to_owned()))
            }
        }
    }

}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct EvenementLecture {
    instance_id: String,
    lecture: MessageMilleGrille,
}

impl EvenementLecture {

    async fn recuperer_info<M>(self, middleware: &M) -> Result<LectureAppareilInfo, Box<dyn Error>>
        where M: VerificateurMessage + ValidateurX509
    {
        let fingerprint_certificat = self.lecture.pubkey.clone();
        let certificat = match &self.lecture.certificat {
            Some(c) => {
                middleware.charger_enveloppe(c, Some(fingerprint_certificat.as_str()), None).await?
            },
            None => {
                match middleware.get_certificat(fingerprint_certificat.as_str()).await {
                    Some(c) => c,
                    None => Err(format!("EvenementLecture Certificat inconnu : {}", fingerprint_certificat))?
                }
            }
        };

        // Valider le message, extraire enveloppe
        let mut message_serialise = MessageSerialise::from_parsed(self.lecture)?;
        message_serialise.certificat = Some(certificat);

        let validation = middleware.verifier_message(&mut message_serialise, None)?;
        if ! validation.valide() { Err(format!("EvenementLecture Evenement de lecture echec validation"))? }

        let lecture: LectureAppareil = message_serialise.parsed.map_contenu()?;

        let (user_id, uuid_appareil) = match message_serialise.certificat {
            Some(c) => {
                let user_id = match c.get_user_id()? {
                    Some(u) => u.to_owned(),
                    None => Err(format!("EvenementLecture Evenement de lecture user_ud manquant du certificat"))?
                };
                debug!("EvenementLecture Certificat lecture subject: {:?}", c.subject());
                let uuid_appareil = match c.subject()?.get("commonName") {
                    Some(s) => s.to_owned(),
                    None => Err(format!("EvenementLecture Evenement de lecture certificat sans uuid_appareil (commonName)"))?
                };
                (user_id, uuid_appareil)
            },
            None => Err(format!("EvenementLecture Evenement de lecture certificat manquant"))?
        };

        Ok(LectureAppareilInfo {
            uuid_appareil,
            user_id,
            lectures_senseurs: lecture.lectures_senseurs,
            displays: lecture.displays,
        })
    }
}


pub async fn evenement_domaine_lecture<M>(middleware: &M, m: &MessageValideAction, gestionnaire: &GestionnaireSenseursPassifs) -> Result<(), Box<dyn Error>>
    where M: ValidateurX509 + VerificateurMessage + GenerateurMessages + MongoDao
{
    debug!("evenement_domaine_lecture Recu evenement {:?}", &m.message);
    let lecture: EvenementLecture = m.message.get_msg().map_contenu()?;
    debug!("Evenement mappe : {:?}", lecture);

    // Extraire instance, convertir evenement en LectureAppareilInfo
    let instance_id = lecture.instance_id.clone();
    let lecture = lecture.recuperer_info(middleware).await?;

    // Trouver date de la plus recente lecture
    let derniere_lecture = lecture.calculer_derniere_lecture();

    let mut filtre = doc! {
        CHAMP_UUID_APPAREIL: &lecture.uuid_appareil,
        "user_id": lecture.user_id.as_str(),
    };

    // Convertir date en format DateTime pour conserver, ajouter filtre pour eviter de
    // mettre a jour un senseur avec informations plus vieilles
    let derniere_lecture_dt = match derniere_lecture.as_ref()  {
        Some(l) => {
            Some(l.get_datetime())
        },
        None => None
    };

    let mut set_ops = doc! {
        CHAMP_INSTANCE_ID: &instance_id,
        "derniere_lecture": &derniere_lecture,
        "derniere_lecture_dt": derniere_lecture_dt,
    };

    // let senseurs = convertir_to_bson(&lecture.senseurs)?;
    for (senseur_id, lecture_senseur) in &lecture.lectures_senseurs {
        set_ops.insert(format!("senseurs.{}", senseur_id), convertir_to_bson(&lecture_senseur)?);
    }
    if let Some(displays) = &lecture.displays {
        debug!("Conserver displays : {:?}", displays);
        set_ops.insert("displays", convertir_to_bson_array(displays.to_owned())?);
    }

    let ops = doc! {
        "$set": set_ops,
        "$setOnInsert": {
            CHAMP_CREATION: Utc::now(),
            CHAMP_UUID_APPAREIL: &lecture.uuid_appareil,
            "user_id": lecture.user_id.as_str(),
        },
        "$currentDate": { CHAMP_MODIFICATION: true },
    };
    let collection = middleware.get_collection(COLLECTIONS_APPAREILS)?;
    let opts = UpdateOptions::builder().upsert(true).build();
    let resultat_update = collection.update_one(filtre, ops, Some(opts)).await?;
    debug!("evenement_domaine_lecture Resultat update : {:?}", resultat_update);

    // Charger etat a partir de mongo - va recuperer dates, lectures d'autres apps
    let info_senseur = {
        let projection = doc! {
            CHAMP_UUID_APPAREIL: 1,
            CHAMP_USER_ID: 1,
            CHAMP_INSTANCE_ID: 1,
            "derniere_lecture": 1,
            CHAMP_SENSEURS: 1,
            "descriptif": 1,
        };
        let filtre = doc! { CHAMP_UUID_APPAREIL: &lecture.uuid_appareil, CHAMP_USER_ID: &lecture.user_id };
        let opts = FindOneOptions::builder().projection(projection).build();
        let collection = middleware.get_collection(COLLECTIONS_APPAREILS)?;
        let doc_senseur = collection.find_one(filtre, opts).await?;

        match doc_senseur {
            Some(d) => {
                match convertir_bson_deserializable::<InformationAppareil>(d) {
                    Ok(info_senseur) => {
                        debug!("Chargement info senseur pour evenement confirmation : {:?}", info_senseur);
                        info_senseur
                    },
                    Err(e) => Err(format!("lectures.evenement_domaine_lecture Erreur mapping InformationAppareil : {:?}", e))?
                }
            },
            None => Err(format!("Erreur chargement senseur a partir de mongo, aucun match sur {}", &lecture.uuid_appareil))?
        }
    };

    // Bouncer l'evenement sur tous les exchanges appropries
    let routage = RoutageMessageAction::builder(DOMAINE_NOM, EVENEMENT_LECTURE_CONFIRMEE)
        .exchanges(vec![Securite::L2Prive])
        .partition(info_senseur.user_id.as_str())
        .build();

    match middleware.emettre_evenement(routage, &info_senseur).await {
        Ok(_) => (),
        Err(e) => warn!("senseurspassifs.evenement_domaine_lecture Erreur emission evenement lecture confirmee : {:?}", e)
    }

    // Split lectures, conserver (volatil avant commit horaire)
    if let Err(e) = ajouter_lecture_db(middleware, &lecture).await {
        warn!("Erreur sauvegarde lectures : {:?}", e);
    }

    Ok(())
}

async fn ajouter_lecture_db<M>(middleware: &M, lecture: &LectureAppareilInfo) -> Result<(), Box<dyn Error>>
    where M: ValidateurX509 + VerificateurMessage + GenerateurMessages + MongoDao
{
    let collection = middleware.get_collection(COLLECTIONS_LECTURES)?;

    for (senseur_id, valeur) in &lecture.lectures_senseurs {

        let heure = heure_juste(valeur.timestamp.get_datetime());

        let filtre = doc!{
            CHAMP_UUID_APPAREIL: &lecture.uuid_appareil,
            "senseur_id": senseur_id,
            "user_id": lecture.user_id.as_str(),
            "heure": &heure,
        };

        let now = Utc::now();

        let set_on_insert = doc! {
            CHAMP_CREATION: &now,
            CHAMP_UUID_APPAREIL: &lecture.uuid_appareil,
            "senseur_id": senseur_id,
            "user_id": lecture.user_id.as_str(),
            "heure": heure,
        };

        let ops = doc! {
            "$push": {
                "lectures": convertir_to_bson(valeur)?,
            },
            "$setOnInsert": set_on_insert,
            "$currentDate": {CHAMP_MODIFICATION: true},
        };

        let opts = UpdateOptions::builder().upsert(true).build();
        let _ = collection.update_one(filtre, ops, Some(opts)).await?;
    }

    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct LecturesCumulees {
    user_id: String,
    heure: Value,
    uuid_appareil: String,
    senseur_id: String,
    lectures: Vec<LectureSenseur>,
}

pub async fn generer_transactions_lectures_horaires<M>(middleware: &M) -> Result<(), Box<dyn Error>>
    where M: ValidateurX509 + VerificateurMessage + GenerateurMessages + MongoDao
{
    // Donner 5 minutes apres l'heure pour completer traitement des evenements/lectures (65 minutes).
    let date_aggregation = Utc::now() - chrono::Duration::minutes(65);

    let filtre = doc! {
        "heure": {"$lte": date_aggregation},
    };

    let collection = middleware.get_collection(COLLECTIONS_LECTURES)?;
    let mut curseur = collection.find(filtre, None).await?;
    while let Some(d) = curseur.next().await {
        match convertir_bson_deserializable::<LecturesCumulees>(d?) {
            Ok(l) => generer_transactions(middleware, l).await?,
            Err(e) => {
                error!("lectures.generer_transactions_lectures_horaires Erreur mapping LecturesCumulees : {:?}", e);
            }
        }
    }

    Ok(())
}

async fn generer_transactions<M>(middleware: &M, lectures: LecturesCumulees) -> Result<(), Box<dyn Error>>
    where M: GenerateurMessages
{
    debug!("generer_transactions heure avant {:?} pour user_id {}, appareil : {}, senseur_id : {}",
        lectures.heure, lectures.user_id, lectures.uuid_appareil, lectures.senseur_id);

    let heure = lectures.heure;
    debug!("Heure : {:?}", heure);

    let heure = convertir_value_mongodate(heure)?;

    // On ne traite pas les donnees de l'heure courante.
    // let mut donnees_lectures: Vec<LectureSenseur> = lectures.lectures.into_iter()
    //     .filter(|l| l.timestamp.get_datetime() < &heure_courante)
    //     .collect();

    // let mut groupes_heures = HashMap::new();
    // for lecture in donnees_lectures.into_iter() {
    //     let heure = heure_juste(lecture.timestamp.get_datetime()).timestamp();
    //     let mut groupe_heure = match groupes_heures.get_mut(&heure) {
    //         Some(g) => g,
    //         None => {
    //             groupes_heures.insert(heure, vec![]);
    //             groupes_heures.get_mut(&heure).expect("get")
    //         }
    //     };
    //     groupe_heure.push(lecture);
    // }

    // Generer transactions pour chaque heure
    // for (heure, groupe) in groupes_heures {
        // let heure_dt = DateEpochSeconds::from_i64(heure);
        // let heure_max = lectures.heure.get_datetime().to_owned() + chrono::Duration::hours(1);
        // debug!("Generer transactions pour heure {:?} (< {:?})", lectures.heure, heure_max);

        let mut val_max: Option<f64> = None;
        let mut val_min: Option<f64> = None;
        // Calcul de moyenne
        let mut val_somme: f64 = 0.0;
        let mut compte_valeurs: u32 = 0;
        let mut fract_max: u8 = 0 ;  // Nombre de digits dans partie fractionnaire (pour round avg)

        for lecture in &lectures.lectures {
            if let Some(valeur) = lecture.valeur {

                fract_max = max(fract_max, compter_fract_digits(valeur));

                // Calcul moyenne
                compte_valeurs += 1;
                val_somme += valeur;

                // Max
                match val_max {
                    Some(v) => {
                        if v < valeur {
                            val_max = Some(valeur);  // Remplacer max
                        }
                    },
                    None => val_max = Some(valeur)
                }

                // Min
                match val_min {
                    Some(v) => {
                        if v > valeur {
                            val_min = Some(valeur);  // Remplacer min
                        }
                    },
                    None => val_min = Some(valeur)
                }
            }
        }

        let moyenne = if compte_valeurs > 0 {
            let moyenne = val_somme / compte_valeurs as f64;
            Some(arrondir(moyenne, fract_max as i32))
        } else {
            None
        };

        let transaction = TransactionLectureHoraire {
            heure,
            user_id: lectures.user_id,
            uuid_appareil: lectures.uuid_appareil,
            senseur_id: lectures.senseur_id,
            lectures: lectures.lectures,
            min: val_min,
            max: val_max,
            avg: moyenne
        };

        let routage = RoutageMessageAction::builder(DOMAINE_NOM, TRANSACTION_SENSEUR_HORAIRE)
            .exchanges(vec![Securite::L4Secure])
            .build();

        debug!("Soumettre transaction : {:?}", transaction);
        middleware.soumettre_transaction(routage, &transaction, false).await?;
    // }

    Ok(())
}

fn heure_juste(date: &DateTime<Utc>) -> DateTime<Utc> {
    date.with_minute(0).expect("with_minutes")
        .with_second(0).expect("with_seconds")
        .with_nanosecond(0).expect("with_nanosecond")
}

pub async fn detecter_presence_appareils<M>(middleware: &M) -> Result<(), Box<dyn Error>>
    where M: ValidateurX509 + VerificateurMessage + GenerateurMessages + MongoDao
{
    {
        // Initialiser flag presence sur nouveaux appareils
        let collection = middleware.get_collection(COLLECTIONS_APPAREILS)?;
        let filtre = doc! {CHAMP_PRESENT: {"$exists": false}};
        let ops = doc! { "$set": {CHAMP_PRESENT: true}, "$currentDate": {CHAMP_MODIFICATION: true} };
        collection.update_many(filtre, ops, None).await?;
    }

    // Detecter appareils presents, absents
    detecter_changement_lectures_appareils(middleware, true).await?;
    detecter_changement_lectures_appareils(middleware, false).await?;

    // TODO - emettre notifications usagers

    Ok(())
}



/// param present : true si detecter changement d'absent vers present, false inverse
async fn detecter_changement_lectures_appareils<M>(middleware: &M, present: bool) -> Result<(), Box<dyn Error>>
    where M: ValidateurX509 + VerificateurMessage + GenerateurMessages + MongoDao
{
    // Date limite pour detecter presence : < est absent, > est present
    let date_limite = Utc::now() - chrono::Duration::minutes(1);

    let filtre = match present {
        true => doc! {
            // Detecter appareils qui etaient absents et sont maintenant presents
            CHAMP_DERNIERE_LECTURE: { "$gte": date_limite },
            CHAMP_PRESENT: false,
        },
        false => doc! {
            // Detecter appareils qui etaient presents et sont maintenant absents
            CHAMP_DERNIERE_LECTURE: { "$lt": date_limite },
            CHAMP_PRESENT: true,
        }
    };

    let options = FindOptions::builder().hint(Hint::Name(INDEX_APPAREILS_DERNIERE_LECTURE.to_string())).build();
    let collection = middleware.get_collection(COLLECTIONS_APPAREILS)?;
    let mut curseur = collection.find(filtre, Some(options)).await?;
    while let Some(r) = curseur.next().await {
        let appareil: InformationAppareil = convertir_bson_deserializable(r?)?;
        debug!("detecter_changement_lectures_appareils Appareil changement presence : {:?}", appareil.uuid_appareil);

        // Mettre a jour l'appareil dans la base de donnees
        let filtre = doc!{
            CHAMP_USER_ID: &appareil.user_id,
            CHAMP_UUID_APPAREIL: &appareil.uuid_appareil
        };
        let ops = doc! {
            "$set": {
                CHAMP_PRESENT: present,
            },
            "$currentDate": { CHAMP_MODIFICATION: true }
        };
        collection.update_one(filtre, ops, None).await?;

        // Ajouter entree de notification pour l'usager
        ajouter_notification_appareil(middleware, &appareil, present).await?;
    }

    Ok(())
}

async fn ajouter_notification_appareil<M>(middleware: &M, appareil: &InformationAppareil, present: bool) -> Result<(), Box<dyn Error>>
    where M: ValidateurX509 + VerificateurMessage + GenerateurMessages + MongoDao
{
    let (champ_present, champ_inverse) = match present {
        true => ("presents", "absents"),
        false => ("absents", "presents")
    };
    let ops = doc! {
        "$setOnInsert": {
            CHAMP_USER_ID: &appareil.user_id,
            CHAMP_CREATION: Utc::now(),
        },
        "$addToSet": { champ_present: &appareil.uuid_appareil },
        "$pull": { champ_inverse: &appareil.uuid_appareil },
        "$currentDate": { CHAMP_MODIFICATION: true }
    };
    let filtre = doc! { CHAMP_USER_ID: &appareil.user_id };
    let options = UpdateOptions::builder().upsert(true).build();

    let collection = middleware.get_collection(COLLECTIONS_NOTIFICATIONS_USAGERS)?;
    collection.update_one(filtre, ops, options).await?;

    Ok(())
}
