use std::cmp::max;
use std::collections::HashMap;
use log::{debug, error, info, warn};
use millegrilles_common_rust::bson::{DateTime as BsonDateTime, doc};
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::{chrono, serde_json};
use millegrilles_common_rust::chrono::{DateTime, NaiveDateTime, Timelike, Utc};
use millegrilles_common_rust::constantes::Securite;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, convertir_to_bson, convertir_to_bson_array, MongoDao};
use millegrilles_common_rust::mongodb::options::{FindOneOptions, FindOptions, Hint, UpdateOptions};
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::serde_json::Value;
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::math::{arrondir, compter_fract_digits};
use millegrilles_common_rust::middleware::{sauvegarder_traiter_transaction, sauvegarder_traiter_transaction_serializable, sauvegarder_traiter_transaction_serializable_v2};
use millegrilles_common_rust::error::Error;
use millegrilles_common_rust::millegrilles_cryptographie::deser_message_buffer;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::{MessageMilleGrillesBufferDefault, MessageMilleGrillesOwned, MessageMilleGrillesRef, MessageMilleGrillesRefDefault, MessageValidable};
use millegrilles_common_rust::recepteur_messages::MessageValide;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::epochseconds;
use millegrilles_common_rust::bson::serde_helpers::chrono_datetime_as_bson_datetime;

use crate::common::*;
use crate::commandes::RowRelais;
use crate::domain_manager::SenseursPassifsDomainManager;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct LectureAppareilInfo {
    uuid_appareil: String,
    user_id: String,
    lectures_senseurs: HashMap<String, LectureSenseur>,
    displays: Option<Vec<ParamsDisplay>>,
    notifications: Option<Vec<NotificationAppareil>>
}

impl LectureAppareilInfo {

    fn calculer_derniere_lecture(&self) -> Option<DateTime<Utc>> {
        let mut date_lecture: DateTime<Utc> = DateTime::<Utc>::MIN_UTC;
        for l in self.lectures_senseurs.values() {
            date_lecture = l.timestamp.max(date_lecture);
        }

        match &date_lecture == &DateTime::<Utc>::MIN_UTC {
            true => {
                None
            },
            false => {
                Some(date_lecture)
            }
        }
    }

}

#[derive(Clone, Serialize, Deserialize)]
struct EvenementLecture {
    instance_id: String,
    lecture: Option<MessageMilleGrillesOwned>,
    lecture_relayee: Option<LectureAppareilInfo>,
}

impl EvenementLecture {

    async fn recuperer_info<M,S>(self, middleware: &M, fingerprint_relai: S) -> Result<LectureAppareilInfo, Error>
        where
            M: ValidateurX509 + MongoDao,
            S: AsRef<str>
    {
        if self.lecture.is_some() {
            // Charger une lecture signee par l'appareil
            self.charger_lecture_directe(middleware).await
        } else if self.lecture_relayee.is_some() {
            // Charger une lecture relayee
            self.charger_lecture_relayee(middleware, fingerprint_relai).await
        } else {
            Err(Error::Str("lectures.EvenementLecture.recuperer_info Aucun contenu lecture/lecture_relayee"))?
        }
    }

    async fn charger_lecture_directe<M>(self, middleware: &M) -> Result<LectureAppareilInfo, Error>
        where M: ValidateurX509
    {
        let lecture = match self.lecture {
            Some(inner) => inner,
            None => Err(Error::Str("lectures.EvenementLecture.charger_lecture_directe Field lecture est vide"))?
        };

        // Recuperer le certificat, valider le message.
        let certificat = {
            let lecture_buffer: MessageMilleGrillesBufferDefault = lecture.clone().try_into()?;
            let mut lecture_ref = lecture_buffer.parse()?;
            lecture_ref.verifier_signature()?;
            middleware.valider_certificat_message(&lecture_ref, true).await?
        };

        let lecture: LectureAppareil = lecture.deserialize()?;
        let user_id = match certificat.get_user_id()? {
            Some(inner) => inner,
            None => Err(Error::Str("lectures.EvenementLecture.charger_lecture_directe Evenement de lecture user_ud manquant du certificat"))?
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
            None => Err(Error::Str("lectures.EvenementLecture.charger_lecture_directe Evenement de lecture certificat sans uuid_appareil (commonName)"))?
        };

        Ok(LectureAppareilInfo {
            uuid_appareil,
            user_id,
            lectures_senseurs: lecture.lectures_senseurs,
            displays: lecture.displays,
            notifications: lecture.notifications,
        })
    }

    async fn charger_lecture_relayee<M,S>(self, middleware: &M, fingerprint_relai: S)
        -> Result<LectureAppareilInfo, Error>
        where
            M: ValidateurX509 + MongoDao,
            S: AsRef<str>
    {
        let fingerprint_relai = fingerprint_relai.as_ref();

        let lecture = match self.lecture_relayee {
            Some(inner) => inner,
            None => Err(format!("lectures.EvenementLecture.charger_lecture_directe Field lecture est vide"))?
        };

        let user_id = lecture.user_id;
        let uuid_appareil = lecture.uuid_appareil;

        // Verifier que le relai est autorise a signer pour cet appareil
        let filtre = doc! {
            CHAMP_USER_ID: &user_id,
            CHAMP_UUID_APPAREIL: &uuid_appareil,
            "fingerprint": fingerprint_relai
        };
        let collection = middleware.get_collection_typed::<RowRelais>(COLLECTIONS_RELAIS)?;
        match collection.find_one(filtre, None).await? {
            Some(inner) => {
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
                Err(format!("charger_lecture_relayee Relai {} non autorise pour appareil {}", fingerprint_relai, uuid_appareil))?
            }
        }
    }
}


pub async fn evenement_domaine_lecture<M>(middleware: &M, m: &MessageValide, gestionnaire: &SenseursPassifsDomainManager)
    -> Result<(), Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    let lecture: EvenementLecture = deser_message_buffer!(m.message);

    let certificat = m.certificat.as_ref();

    let fingerprint_relai = certificat.fingerprint()?;

    // Extraire instance, convertir evenement en LectureAppareilInfo
    let instance_id = lecture.instance_id.clone();
    let lecture = lecture.recuperer_info(middleware, fingerprint_relai).await?;

    // Trouver date de la plus recente lecture
    let derniere_lecture = lecture.calculer_derniere_lecture();

    let mut filtre = doc! {
        CHAMP_UUID_APPAREIL: &lecture.uuid_appareil,
        "user_id": lecture.user_id.as_str(),
    };

    // Convertir date en format DateTime pour conserver, ajouter filtre pour eviter de
    // mettre a jour un senseur avec informations plus vieilles
    let derniere_lecture_dt = derniere_lecture.as_ref();

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
    let routage = RoutageMessageAction::builder(DOMAINE_NOM, EVENEMENT_LECTURE_CONFIRMEE, vec![Securite::L2Prive])
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

    // // Traiter notifications evenement
    // if let Some(notifications) = lecture.notifications {
    //     debug!("recuperer_info Traiter notifications messages : {:?}", notifications);
    //     for notification in notifications {
    //         let notif_info = NotificationAppareilUsager {
    //             user_id: lecture.user_id.clone(),
    //             uuid_appareil: lecture.uuid_appareil.clone(),
    //             notification,
    //         };
    //         if let Err(e) = emettre_notification_appareil_usager(middleware, notif_info).await {
    //             warn!("Erreur emission notifications appareil : {:?}", e);
    //         }
    //     }
    // }

    Ok(())
}

async fn ajouter_lecture_db<M>(middleware: &M, lecture: &LectureAppareilInfo) -> Result<(), Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    let collection = middleware.get_collection(COLLECTIONS_LECTURES)?;

    for (senseur_id, valeur) in &lecture.lectures_senseurs {

        let heure = heure_juste(&valeur.timestamp);

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
    #[serde(
        serialize_with = "epochseconds::serialize",
        deserialize_with = "chrono_datetime_as_bson_datetime::deserialize"
    )]
    heure: DateTime<Utc>,
    uuid_appareil: String,
    senseur_id: String,
    lectures: Vec<LectureSenseur>,
}

pub async fn generer_transactions_lectures_horaires<M>(middleware: &M, gestionnaire: &SenseursPassifsDomainManager) -> Result<(), Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
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
            Ok(l) => generer_transactions(middleware, gestionnaire, l).await?,
            Err(e) => {
                error!("lectures.generer_transactions_lectures_horaires Erreur mapping LecturesCumulees : {:?}", e);
            }
        }
    }

    Ok(())
}

async fn generer_transactions<M>(middleware: &M, gestionnaire: &SenseursPassifsDomainManager, lectures: LecturesCumulees) -> Result<(), Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("generer_transactions heure avant {:?} pour user_id {}, appareil : {}, senseur_id : {}",
        lectures.heure, lectures.user_id, lectures.uuid_appareil, lectures.senseur_id);

    let heure = lectures.heure;
    debug!("Heure : {:?}", heure);

    // let heure = convertir_value_mongodate(heure)?;

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
        // let heure_dt = DateTime<Utc>::from_i64(heure);
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

        // let routage = RoutageMessageAction::builder(DOMAINE_NOM, TRANSACTION_SENSEUR_HORAIRE, vec![Securite::L4Secure])
        //     .blocking(false)
        //     .build();

        debug!("Soumettre transaction : {:?}", transaction);
        // middleware.soumettre_transaction(routage, &transaction).await?;
        if let Err(e) = sauvegarder_traiter_transaction_serializable_v2(
            middleware, &transaction, gestionnaire, DOMAINE_NOM, TRANSACTION_SENSEUR_HORAIRE).await
        {
            error!("generer_transactions Erreur traitemnet transaction {:?}", e)
        }
    // }

    Ok(())
}

fn heure_juste(date: &DateTime<Utc>) -> DateTime<Utc> {
    date.with_minute(0).expect("with_minutes")
        .with_second(0).expect("with_seconds")
        .with_nanosecond(0).expect("with_nanosecond")
}

// pub async fn detecter_presence_appareils<M>(middleware: &M) -> Result<(), Error>
//     where M: GenerateurMessages + MongoDao + EmetteurNotificationsTrait
// {
//     {
//         // Initialiser flag presence sur nouveaux appareils
//         let collection = middleware.get_collection(COLLECTIONS_APPAREILS)?;
//         let filtre = doc! {CHAMP_PRESENT: {"$exists": false}};
//         let ops = doc! { "$set": {CHAMP_PRESENT: true}, "$currentDate": {CHAMP_MODIFICATION: true} };
//         collection.update_many(filtre, ops, None).await?;
//     }
//
//     // Detecter appareils presents, absents
//     detecter_changement_lectures_appareils(middleware, true).await?;
//     detecter_changement_lectures_appareils(middleware, false).await?;
//
//     // Emettre notifications pending pour tous les usagers
//     // emettre_notifications_usagers(middleware).await?;
//
//     Ok(())
// }

/// param present : true si detecter changement d'absent vers present, false inverse
async fn detecter_changement_lectures_appareils<M>(middleware: &M, present: bool) -> Result<(), Error>
    where M:  MongoDao
{
    // Date limite pour detecter presence : < est absent, > est present
    let date_limite = Utc::now() - chrono::Duration::seconds(CONST_APAREIL_LECTURE_TIMEOUT_SECS);

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
        let mut ops = doc! {
            "$set": {
                CHAMP_PRESENT: present,
            },
            "$currentDate": { CHAMP_MODIFICATION: true }
        };
        // Retirer le champ connecte (on n'a aucune information)
        if ! present {
            ops.insert("$unset", doc!{CHAMP_CONNECTE: true});
        }
        collection.update_one(filtre, ops, None).await?;

        // Ajouter entree de notification pour l'usager
        ajouter_notification_appareil(middleware, &appareil, present).await?;
    }

    Ok(())
}

async fn ajouter_notification_appareil<M>(middleware: &M, appareil: &InformationAppareil, present: bool) -> Result<(), Error>
    where M: MongoDao
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
        "$set": { CHAMP_DIRTY: true },
        "$currentDate": { CHAMP_MODIFICATION: true }
    };
    let filtre = doc! { CHAMP_USER_ID: &appareil.user_id };
    let options = UpdateOptions::builder().upsert(true).build();

    let collection = middleware.get_collection(COLLECTIONS_NOTIFICATIONS_USAGERS)?;
    collection.update_one(filtre, ops, options).await?;

    Ok(())
}


// async fn emettre_notifications_usagers<M>(middleware: &M) -> Result<(), Error>
//     where M: GenerateurMessages + MongoDao + EmetteurNotificationsTrait
// {
//     let filtre = doc!{
//         CHAMP_DIRTY: true,
//     };
//     let collection = middleware.get_collection(COLLECTIONS_NOTIFICATIONS_USAGERS)?;
//     let mut curseur = collection.find(filtre, None).await?;
//     while let Some(r) = curseur.next().await {
//         let doc_usager: DocumentNotificationUsager = convertir_bson_deserializable(r?)?;
//
//         // Reset flag usager
//         let filtre = doc! { CHAMP_USER_ID: &doc_usager.user_id };
//         let ops = doc! {
//             "$set": {CHAMP_DIRTY: false},
//             "$unset": {CHAMP_PRESENTS: true, CHAMP_ABSENTS: true},
//             "$currentDate": {CHAMP_MODIFICATION: true},
//         };
//         collection.update_one(filtre, ops, None).await?;
//
//         // Preparer et emettre la notification
//         emettre_notification_usager(middleware, &doc_usager).await?;
//     }
//
//     Ok(())
// }

// async fn emettre_notification_usager<M>(middleware: &M, doc_usager: &DocumentNotificationUsager) -> Result<(), Error>
//     where M: GenerateurMessages + MongoDao + EmetteurNotificationsTrait
// {
//     let now = Utc::now();
//
//     let mut uuid_appareils = Vec::new();
//
//     let nombre_presents = match doc_usager.presents.as_ref() {
//         Some(inner) => {
//             for app in inner {
//                 uuid_appareils.push(app.as_str());
//             }
//             inner.len()
//         },
//         None => 0
//     };
//     let nombre_absents = match doc_usager.absents.as_ref() {
//         Some(inner) => {
//             for app in inner {
//                 uuid_appareils.push(app.as_str());
//             }
//             inner.len()
//         },
//         None => 0
//     };
//
//     let mut map_appareils = HashMap::new();
//     let filtre = doc! {
//         CHAMP_USER_ID: &doc_usager.user_id,
//         CHAMP_UUID_APPAREIL: {"$in": uuid_appareils}
//     };
//     debug!("emettre_notification_usager Filtre chargement appareils : {:?}", filtre);
//     let collection = middleware.get_collection(COLLECTIONS_APPAREILS)?;
//     let mut curseur = collection.find(filtre, None).await?;
//     while let Some(r) = curseur.next().await {
//         let app: InformationAppareil = convertir_bson_deserializable(r?)?;
//         debug!("emettre_notification_usager Appareil charge : {:?}", app);
//         map_appareils.insert(app.uuid_appareil.to_owned(), app);
//     }
//
//     let sujet = format!("Notifications pour {} appareils ({} avec contact perdu)", nombre_presents+nombre_absents, nombre_absents);
//
//     let mut contenu = String::new();
//     if let Some(appareils) = doc_usager.presents.as_ref() {
//         contenu.push_str("<h2>Appareils reconnectes</h2><br/>\n");
//         for app in appareils {
//             let ligne = match map_appareils.get(app) {
//                 Some(inner) => {
//                     match inner.configuration.as_ref() {
//                         Some(config) => match config.descriptif.as_ref() {
//                             Some(descriptif) =>  format!("{}<br/>", descriptif),
//                             None => format!("{}<br/>", app.as_str())
//                         },
//                         None => format!("{}<br/>", app.as_str())
//                     }
//                 },
//                 None => format!("{}<br/>", app.as_str())
//             };
//             contenu.push_str(ligne.as_str());
//         }
//         contenu.push_str("<br/>\n")
//     }
//
//     if let Some(appareils) = doc_usager.absents.as_ref() {
//         contenu.push_str("<h2>Appareils deconnectes</h2><br/>\n");
//         for app in appareils {
//             let ligne = match map_appareils.get(app) {
//                 Some(inner) => {
//                     match inner.configuration.as_ref() {
//                         Some(config) => match config.descriptif.as_ref() {
//                             Some(descriptif) =>  format!("{} (derniere lecture : {:?})<br/>", descriptif, inner.derniere_lecture),
//                             None => format!("{}<br/>", app.as_str())
//                         },
//                         None => format!("{}<br/>", app.as_str())
//                     }
//                 },
//                 None => format!("{}<br/>", app.as_str())
//             };
//             contenu.push_str(ligne.as_str());
//         }
//         contenu.push_str("</br/>\n")
//     }
//
//     // Charger cle notifications usager - creer nouvelle cle au besoin
//     let cle_usager = match doc_usager.cle_id.as_ref() {
//         Some(cle_id) => {
//             debug!("Charger cle_id {}", cle_id);
//             let mut cles_dechiffrees = get_cles_dechiffrees(
//                 middleware, vec![cle_id.clone()], Some(DOMAINE_NOM)).await?;
//             match cles_dechiffrees.remove(cle_id) {
//                 Some(inner) => Some(inner),
//                 None => {
//                     warn!("Erreur reception cle dechiffrage notifications usager : {}, creer nouvelle cle", doc_usager.user_id);
//                     None
//                 }
//             }
//         },
//         None => {
//             debug!("Generer nouvelle cle de notification pour usager {}", doc_usager.user_id);
//             None
//         }
//     };
//
//     let notification = NotificationMessageInterne {
//         from: "SenseursPassifs".to_string(),
//         subject: Some(sujet),
//         content: contenu,
//         version: 1,
//         format: "html".to_string(),
//     };
//
//     debug!("Emettre notification usager : {:?}", notification);
//
//     let cle_id = middleware.emettre_notification_usager(
//         doc_usager.user_id.as_str(), notification,
//         "info",
//         DOMAINE_NOM,
//         Some(now.timestamp() + 3 * 86400),
//         cle_usager
//     ).await?;
//
//     if doc_usager.cle_id.is_none() {
//         debug!("Conserver cle_id {} pour usager {}", cle_id, doc_usager.user_id);
//         let filtre = doc! { CHAMP_USER_ID: &doc_usager.user_id };
//         let ops = doc! {
//             "$set": { "cle_id": &cle_id },
//             "$currentDate": { CHAMP_MODIFICATION: true }
//         };
//         let collection = middleware.get_collection(COLLECTIONS_NOTIFICATIONS_USAGERS)?;
//         collection.update_one(filtre, ops, None).await?;
//     }
//
//     Ok(())
// }

// async fn emettre_notification_appareil_usager<M>(middleware: &M, notification_appareil: NotificationAppareilUsager) -> Result<(), Error>
//     where M: GenerateurMessages + MongoDao + EmetteurNotificationsTrait
// {
//     let now = Utc::now();
//
//     let doc_usager: Option<DocumentNotificationUsager> = {
//         let collection = middleware.get_collection(COLLECTIONS_NOTIFICATIONS_USAGERS)?;
//         let filtre = doc!("user_id": &notification_appareil.user_id);
//         let doc_usager = collection.find_one(filtre, None).await?;
//         match doc_usager {
//             Some(inner) => {
//                 let du: DocumentNotificationUsager = convertir_bson_deserializable(inner)?;
//                 Some(du)
//             },
//             None => None
//         }
//     };
//
//     let filtre = doc! {
//         CHAMP_USER_ID: &notification_appareil.user_id,
//         CHAMP_UUID_APPAREIL: &notification_appareil.uuid_appareil,
//     };
//     debug!("emettre_notification_usager Filtre chargement appareils : {:?}", filtre);
//     let collection = middleware.get_collection(COLLECTIONS_APPAREILS)?;
//     let doc_appareil: InformationAppareil = match collection.find_one(filtre, None).await? {
//         Some(doc_appareil) => convertir_bson_deserializable(doc_appareil)?,
//         None => Err(format!("lectures.emettre_notification_appareil_usager Appareil {} inconnu", notification_appareil.uuid_appareil))?
//     };
//
//     let descriptif_appareil = doc_appareil.get_descriptif();
//
//     let sujet = format!("Notification pour {}", descriptif_appareil);
//
//     let mut contenu = String::new();
//     contenu.push_str("<h2>Notification</h2><br/>\n");
//     match notification_appareil.notification.message {
//         Some(message) => {
//             contenu.push_str(format!("<p>{}</p><br/>\n", message).as_str());
//         },
//         None => {
//             contenu.push_str("<p>Aucun message.</p>\n")
//         }
//     }
//     contenu.push_str("<br/>\n");
//
//     // Charger cle notifications usager - creer nouvelle cle au besoin
//     let cle_usager = match &doc_usager {
//         Some(d) => {
//             match &d.cle_id {
//                 Some(cle_id) => {
//                     charger_cle_notification_usager(
//                         middleware, cle_id.as_ref(), notification_appareil.user_id.as_str()).await?
//                 },
//                 None => None,
//             }
//         },
//         None => None
//     };
//
//     let notification = NotificationMessageInterne {
//         from: "SenseursPassifs".to_string(),
//         subject: Some(sujet),
//         content: contenu,
//         version: 1,
//         format: "html".to_string(),
//     };
//
//     debug!("Emettre notification appareil usager : {:?}", notification);
//
//     let cle_presente = cle_usager.is_some();
//
//     let cle_id = middleware.emettre_notification_usager(
//         notification_appareil.user_id.as_str(), notification,
//         "info",
//         DOMAINE_NOM,
//         Some(now.timestamp() + 3 * 86400),
//         cle_usager
//     ).await?;
//
//     if cle_presente == false {
//         debug!("Conserver cle_id {} pour usager {}", cle_id, notification_appareil.user_id);
//         let filtre = doc! { CHAMP_USER_ID: &notification_appareil.user_id };
//         let ops = doc! {
//             "$set": { "cle_id": &cle_id },
//             "$currentDate": { CHAMP_MODIFICATION: true }
//         };
//         let collection = middleware.get_collection(COLLECTIONS_NOTIFICATIONS_USAGERS)?;
//         collection.update_one(filtre, ops, None).await?;
//     }
//
//     Ok(())
// }

// async fn charger_cle_notification_usager<M>(middleware: &M, cle_id: &str, user_id: &str)
//     -> Result<Option<CleDechiffree>, Error>
//     where M: GenerateurMessages
// {
//     debug!("charger_cle_notification_usager Charger cle_id {}", cle_id);
//     let mut cles_dechiffrees = match get_cles_dechiffrees(middleware, vec![cle_id.clone()], Some(DOMAINE_NOM)).await {
//         Ok(inner) => inner,
//         Err(e) => Err(format!("lectures.charger_cle_notification_usager Erreur get_cles_dechiffrees : {:?}", e))?
//     };
//     match cles_dechiffrees.remove(cle_id) {
//         Some(inner) => Ok(Some(inner)),
//         None => {
//             warn!("Erreur reception cle dechiffrage notifications usager : {}, creer nouvelle cle", user_id);
//             Ok(None)
//         }
//     }
// }
