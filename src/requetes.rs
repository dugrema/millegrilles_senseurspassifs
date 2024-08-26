use std::collections::{BTreeMap, HashMap};
use log::{debug, error, info};
use chrono_tz::Tz;

use millegrilles_common_rust::bson::{doc, Document};

use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chrono::{Duration, Timelike, Utc, TimeZone, DateTime as ChronoDateTime, NaiveDateTime, DateTime};
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, convertir_bson_value, filtrer_doc_id, MongoDao};
use millegrilles_common_rust::mongodb::options::{FindOneOptions, FindOptions};
use millegrilles_common_rust::recepteur_messages::{MessageValide, TypeMessage};
use millegrilles_common_rust::serde_json::{json, Value};
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::error::Error;
use millegrilles_common_rust::{get_domaine_action, serde_json};
use millegrilles_common_rust::millegrilles_cryptographie::deser_message_buffer;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::rabbitmq_dao::TypeMessageOut;
use millegrilles_common_rust::bson::serde_helpers::chrono_datetime_as_bson_datetime;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::{epochseconds, optionepochseconds};

use crate::senseurspassifs::GestionnaireSenseursPassifs;
use crate::common::*;

pub async fn consommer_requete<M>(middleware: &M, message: MessageValide, gestionnaire: &GestionnaireSenseursPassifs)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("Consommer requete : {:?}", &message.type_message);

    // Autorisation : On accepte les requetes de 3.protege ou 4.secure
    let exchanges_ok = message.certificat.verifier_exchanges(vec![Securite::L2Prive, Securite::L3Protege, Securite::L4Secure])?;
    let delegation_globale = message.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)?;
    let user_id = message.certificat.get_user_id()?;

    let (domaine, action) = get_domaine_action!(message.type_message);

    if exchanges_ok || delegation_globale {
        match domaine.as_str() {
            DOMAINE_NOM => {
                match action.as_str() {
                    REQUETE_GET_APPAREILS_USAGER => requete_appareils_usager(middleware, message, gestionnaire).await,
                    REQUETE_GET_APPAREIL_DISPLAY_CONFIGURATION => requete_appareil_display_configuration(middleware, message, gestionnaire).await,
                    REQUETE_GET_APPAREIL_PROGRAMMES_CONFIGURATION => requete_appareil_programmes_configuration(middleware, message, gestionnaire).await,
                    REQUETE_LISTE_NOEUDS => requete_liste_noeuds(middleware, message, gestionnaire).await,
                    REQUETE_LISTE_SENSEURS_PAR_UUID => requete_liste_senseurs_par_uuid(middleware, message, gestionnaire).await,
                    REQUETE_LISTE_SENSEURS_NOEUD => requete_liste_senseurs_pour_noeud(middleware, message, gestionnaire).await,
                    REQUETE_GET_NOEUD => requete_get_noeud(middleware, message, gestionnaire).await,
                    REQUETE_GET_APPAREILS_EN_ATTENTE => requete_get_appareils_en_attente(middleware, message, gestionnaire).await,
                    REQUETE_GET_STATISTIQUES_SENSEUR => requete_get_statistiques_senseur(middleware, message, gestionnaire).await,
                    REQUETE_GET_CONFIGURATION_USAGER => requete_get_configuration_usager(middleware, message, gestionnaire).await,
                    REQUETE_GET_TIMEZONE_APPAREIL => requete_get_timezone_appareil(middleware, message, gestionnaire).await,
                    _ => {
                        error!("Message requete/action inconnue : '{}'. Message dropped.", action);
                        Ok(None)
                    },
                }
            },
            _ => {
                error!("Message requete/domaine inconnu : '{}'. Message dropped.", domaine);
                Ok(None)
            },
        }
    } else if user_id.is_some() {
        match domaine.as_str() {
            DOMAINE_NOM => {
                match action.as_str() {
                    REQUETE_GET_APPAREILS_USAGER => requete_appareils_usager(middleware, message, gestionnaire).await,
                    REQUETE_GET_APPAREIL_DISPLAY_CONFIGURATION => requete_appareil_display_configuration(middleware, message, gestionnaire).await,
                    REQUETE_GET_APPAREIL_PROGRAMMES_CONFIGURATION => requete_appareil_programmes_configuration(middleware, message, gestionnaire).await,
                    REQUETE_GET_APPAREILS_EN_ATTENTE => requete_get_appareils_en_attente(middleware, message, gestionnaire).await,
                    REQUETE_GET_STATISTIQUES_SENSEUR => requete_get_statistiques_senseur(middleware, message, gestionnaire).await,
                    REQUETE_GET_CONFIGURATION_USAGER => requete_get_configuration_usager(middleware, message, gestionnaire).await,
                    _ => {
                        error!("Message requete/action inconnue : '{}'. Message dropped.", action);
                        Ok(None)
                    },
                }
            },
            _ => {
                error!("Message requete/domaine inconnu : '{}'. Message dropped.", domaine);
                Ok(None)
            },
        }
    } else {
        error!("Message autorisation refusee : '{}'. Message dropped.", domaine);
        Ok(None)
    }
}
#[derive(Deserialize)]
struct RequeteAppareilsUsager {
}

#[derive(Serialize)]
struct ReponseAppareilUsager {
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
struct ReponseAppareilsUsager {
    ok: bool,
    appareils: Vec<ReponseAppareilUsager>,
    instance_id: String,
}

async fn requete_appareils_usager<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireSenseursPassifs)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao
{
    debug!("requete_appareils_usager Consommer requete : {:?}", & m.type_message);
    let requete: RequeteAppareilsUsager = deser_message_buffer!(m.message);

    let user_id = match m.certificat.get_user_id()? {
        Some(inner) => inner,
        None => {
            // let reponse = json!({"ok": false, "err": "user_id manquant"});
            // return Ok(Some(middleware.formatter_reponse(&reponse, None)?));
            return Ok(Some(middleware.reponse_err(None, None, Some("user_id manquant"))?))
        }
    };

    let appareils = {
        let mut appareils = Vec::new();

        let filtre = doc! { CHAMP_USER_ID: &user_id /*, CHAMP_INSTANCE_ID: {"$exists": true} */ };

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

        let collection = middleware.get_collection(COLLECTIONS_APPAREILS)?;

        let opts = FindOptions::builder()
            .projection(projection)
            .limit(100)
            .build();
        let mut curseur = collection.find(filtre, opts).await?;

        while let Some(d) = curseur.next().await {
            match convertir_bson_deserializable::<DocAppareil>(d?) {
                Ok(a) => {
                    // appareils.push(a)
                    // Convertir a type reponse
                    let app = ReponseAppareilUsager::from(a);
                    appareils.push(app);
                },
                Err(e) => {
                    info!("Erreur mapping DocAppareil user_id {}", user_id);
                    continue
                }
            }
        }

        appareils
    };

    // let reponse = json!({ "ok": true, "appareils": appareils, "instance_id": &gestionnaire.instance_id });
    let reponse = ReponseAppareilsUsager {ok: true, appareils, instance_id: gestionnaire.instance_id.clone()};
    Ok(Some(middleware.build_reponse(&reponse)?.0))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteAppareilsDisplayConfiguration {
    // uuid_appareil: String,  // Extrait du certificat, comme user_id
}

async fn requete_appareil_display_configuration<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireSenseursPassifs)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao
{
    debug!("requete_appareil_display_configuration Consommer requete : {:?}", & m.message);
    let requete: RequeteAppareilsDisplayConfiguration = deser_message_buffer!(m.message);

    // Extraire user_id, uuid_appareil du certificat
    let user_id = match m.certificat.get_user_id()? {
        Some(u) => u.to_owned(),
        None => Err(format!("EvenementLecture Evenement de lecture user_id manquant du certificat"))?
    };
    debug!("EvenementLecture Certificat lecture subject: {:?}", m.certificat.subject());
    let uuid_appareil = match m.certificat.subject()?.get("commonName") {
        Some(s) => s.to_owned(),
        None => Err(format!("EvenementLecture Evenement de lecture certificat sans uuid_appareil (commonName)"))?
    };

    let display_configuration = {
        let filtre = doc! { CHAMP_USER_ID: user_id, CHAMP_UUID_APPAREIL: uuid_appareil };

        let projection = doc! {
            CHAMP_UUID_APPAREIL: 1,
            CHAMP_INSTANCE_ID: 1,
            "derniere_lecture": 1,
            "configuration.displays": 1,
            "configuration.descriptif": 1,
        };

        let collection = middleware.get_collection(COLLECTIONS_APPAREILS)?;

        let opts = FindOneOptions::builder().projection(projection).build();
        let document_configuration = collection.find_one(filtre, opts).await?;
        match document_configuration {
            Some(d) => {
                let display_configuration: DocAppareil = convertir_bson_deserializable(d)?;
                display_configuration
            },
            None => {
                // let reponse = json!({"ok": false, "err": "appareil inconnu"});
                // return Ok(Some(middleware.formatter_reponse(&reponse, None)?));
                return Ok(Some(middleware.reponse_err(None, None, Some("appareil inconnu"))?))
            }
        }
    };

    let reponse = json!({ "ok": true, "display_configuration": display_configuration });
    Ok(Some(middleware.build_reponse(&reponse)?.0))
}

#[derive(Serialize)]
struct ReponseRequeteAppareilProgrammesConfiguration {
    ok: bool,
    programmes: Option<DocAppareil>,
}

async fn requete_appareil_programmes_configuration<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireSenseursPassifs)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao
{
    debug!("requete_appareil_programmes_configuration Consommer requete : {:?}", & m.message);
    let requete: RequeteAppareilsDisplayConfiguration = deser_message_buffer!(m.message);

    // Extraire user_id, uuid_appareil du certificat
    let user_id = match m.certificat.get_user_id()? {
        Some(u) => u.to_owned(),
        None => Err(format!("requete_appareil_programmes_configuration user_id manquant du certificat"))?
    };
    debug!("EvenementLecture Certificat lecture subject: {:?}", m.certificat.subject());
    let uuid_appareil = match m.certificat.subject()?.get("commonName") {
        Some(s) => s.to_owned(),
        None => Err(format!("requete_appareil_programmes_configuration Certificat sans uuid_appareil (commonName)"))?
    };

    let display_configuration = {
        let filtre = doc! { CHAMP_USER_ID: user_id, CHAMP_UUID_APPAREIL: uuid_appareil };

        let projection = doc! {
            CHAMP_UUID_APPAREIL: 1,
            CHAMP_INSTANCE_ID: 1,
            "derniere_lecture": 1,
            "configuration.programmes": 1,
        };

        let collection = middleware.get_collection(COLLECTIONS_APPAREILS)?;

        let opts = FindOneOptions::builder().projection(projection).build();
        let document_configuration = collection.find_one(filtre, opts).await?;
        match document_configuration {
            Some(d) => {
                let display_configuration: DocAppareil = convertir_bson_deserializable(d)?;
                display_configuration
            },
            None => {
                // let reponse = json!({"ok": false, "err": "appareil inconnu"});
                // return Ok(Some(middleware.formatter_reponse(&reponse, None)?));
                return Ok(Some(middleware.reponse_err(None, None, Some("appareil inconnu"))?))
            }
        }
    };

    let reponse = ReponseRequeteAppareilProgrammesConfiguration {
        ok: true,
        programmes: Some(display_configuration),
    };

    // let reponse = json!({ "ok": true, "programmes": display_configuration });
    Ok(Some(middleware.build_reponse(&reponse)?.0))
}

async fn requete_liste_noeuds<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireSenseursPassifs)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao
{
    debug!("requete_liste_noeuds Consommer requete : {:?}", & m.message);

    let noeuds = {
        let filtre = doc! { };
        let projection = doc! {
            CHAMP_INSTANCE_ID: 1,
            "securite": 1,
            CHAMP_MODIFICATION: 1,
            "descriptif": 1,
        };
        let opts = FindOptions::builder().projection(projection).build();
        let collection = middleware.get_collection(COLLECTIONS_INSTANCES)?;
        let mut curseur = collection.find(filtre, opts).await?;

        let mut noeuds = Vec::new();
        while let Some(d) = curseur.next().await {
            let noeud: TransactionMajNoeud = convertir_bson_deserializable(d?)?;
            noeuds.push(noeud);
        }

        noeuds
    };

    let reponse = json!({ "ok": true, "instances": noeuds, "instance_id": &gestionnaire.instance_id });
    Ok(Some(middleware.build_reponse(&reponse)?.0))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteSenseursParUuid {
    uuid_senseurs: Vec<String>,
}

async fn requete_liste_senseurs_par_uuid<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireSenseursPassifs)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao
{
    debug!("requete_liste_senseurs_par_uuid Consommer requete : {:?}", & m.message);
    let requete: RequeteSenseursParUuid = deser_message_buffer!(m.message);

    let senseurs = {
        let filtre = doc! { CHAMP_UUID_SENSEUR: {"$in": &requete.uuid_senseurs} };
        let projection = doc! {
            CHAMP_UUID_SENSEUR: 1,
            CHAMP_INSTANCE_ID: 1,
            // CHAMP_MODIFICATION: 1,
            "derniere_lecture": 1,
            CHAMP_SENSEURS: 1,
            "securite": 1,
            "descriptif": 1,
            CHAMP_CONNECTE: 1,
            CHAMP_VERSION: 1,
        };
        let opts = FindOptions::builder().projection(projection).build();
        let collection = middleware.get_collection(COLLECTIONS_LECTURES)?;
        let mut curseur = collection.find(filtre, opts).await?;

        let mut senseurs = Vec::new();
        while let Some(d) = curseur.next().await {
            let mut noeud: InformationAppareil = convertir_bson_deserializable(d?)?;
            senseurs.push(noeud);
        }

        senseurs
    };

    let reponse = json!({ "ok": true, "senseurs": senseurs, "instance_id": &gestionnaire.instance_id });
    let reponse_formattee = middleware.build_reponse(&reponse)?.0;
    debug!("Reponse formattee : {:?}", reponse_formattee);
    Ok(Some(reponse_formattee))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteSenseursPourNoeud {
    instance_id: String,
}

async fn requete_liste_senseurs_pour_noeud<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireSenseursPassifs)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao
{
    debug!("requete_liste_senseurs_pour_noeud Consommer requete : {:?}", & m.message);
    let requete: RequeteSenseursPourNoeud = deser_message_buffer!(m.message);

    let senseurs = {
        let filtre = doc! { CHAMP_INSTANCE_ID: &requete.instance_id };
        let projection = doc! {
            CHAMP_UUID_SENSEUR: 1,
            CHAMP_INSTANCE_ID: 1,
            "derniere_lecture": 1,
            CHAMP_SENSEURS: 1,
            "securite": 1,
            "descriptif": 1,
            CHAMP_CONNECTE: 1,
            CHAMP_VERSION: 1,
        };
        let opts = FindOptions::builder().projection(projection).build();
        let collection = middleware.get_collection(COLLECTIONS_LECTURES)?;
        let mut curseur = collection.find(filtre, opts).await?;

        let mut senseurs = Vec::new();
        while let Some(d) = curseur.next().await {
            debug!("Document senseur bson : {:?}", d);
            let mut noeud: InformationAppareil = convertir_bson_deserializable(d?)?;
            senseurs.push(noeud);
        }

        senseurs
    };

    let reponse = json!({ "ok": true, "senseurs": senseurs, "instance_id": &gestionnaire.instance_id });
    let reponse_formattee = middleware.build_reponse(&reponse)?.0;
    debug!("Reponse formattee : {:?}", reponse_formattee);
    Ok(Some(reponse_formattee))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteGetNoeud {
    instance_id: String
}

async fn requete_get_noeud<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireSenseursPassifs)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao
{
    debug!("requete_get_noeud Consommer requete : {:?}", & m.message);
    let requete: RequeteGetNoeud = deser_message_buffer!(m.message);

    let noeud = {
        let filtre = doc! { };
        let projection = doc! {
            CHAMP_INSTANCE_ID: 1,
            "securite": 1,
            CHAMP_MODIFICATION: 1,
            "descriptif": 1,
            "lcd_actif": 1, "lcd_affichage": 1,
        };
        let filtre = doc! { CHAMP_INSTANCE_ID: &requete.instance_id };
        let opts = FindOneOptions::builder().projection(projection).build();
        let collection = middleware.get_collection(COLLECTIONS_INSTANCES)?;
        let mut doc = collection.find_one(filtre, opts).await?;

        match doc {
            Some(mut n) => {
                filtrer_doc_id(&mut n);
                Some(convertir_bson_value(n)?)
            },
            None => None
        }
    };

    let reponse = match noeud {
        Some(mut val_noeud) => {
            // Inserer valeurs manquantes pour la response
            if let Some(mut o) = val_noeud.as_object_mut() {
                o.insert("ok".into(), Value::Bool(true));
                o.insert("instance_id".into(), Value::String(gestionnaire.instance_id.clone()));
            }
            val_noeud
        },
        None => {
            // Confirmer que la requete s'est bien executee mais rien trouve
            json!({ "ok": true, "instance_id": &gestionnaire.instance_id})
        }
    };

    debug!("requete_get_noeud Reponse : {:?}", reponse);

    Ok(Some(middleware.build_reponse(&reponse)?.0))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteGetAppareilsEnAttente {
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ReponseGetAppareilsEnAttente {
    appareils: Vec<DocAppareil>,
}

async fn requete_get_appareils_en_attente<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireSenseursPassifs)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao
{
    debug!("requete_get_appareils_en_attente Consommer requete : {:?}", & m.message);
    let requete: RequeteGetAppareilsEnAttente = deser_message_buffer!(m.message);

    let user_id = match m.certificat.get_user_id()? {
        Some(inner) => inner,
        None => {
            // let reponse = json!({"ok": false, "err": "user_id manquant"});
            // return Ok(Some(middleware.formatter_reponse(&reponse, None)?));
            return Ok(Some(middleware.reponse_err(None, None, Some("user_id manquant"))?))
        }
    };

    let appareils = {
        let mut appareils = Vec::new();

        let projection = doc! {
            CHAMP_UUID_APPAREIL: 1,
            CHAMP_INSTANCE_ID: 1,
            CHAMP_MODIFICATION: 1,
        };
        let filtre = doc! {
            CHAMP_USER_ID: &user_id,
            "csr": {"$exists": true}
        };
        let opts = FindOptions::builder()
            .projection(projection)
            .limit(100)
            .build();
        let collection = middleware.get_collection(COLLECTIONS_APPAREILS)?;

        let mut curseur = collection.find(filtre, opts).await?;
        while let Some(d) = curseur.next().await {
            let appareil: DocAppareil = convertir_bson_deserializable(d?)?;
            appareils.push(appareil);
        }

        appareils
    };

    let reponse = json!({
        "ok": true,
        "instance_id": &gestionnaire.instance_id,
        "appareils": appareils,
    });

    debug!("requete_get_appareils_en_attente Reponse : {:?}", reponse);

    Ok(Some(middleware.build_reponse(&reponse)?.0))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteGetStatistiquesSenseur {
    uuid_appareil: String,
    senseur_id: String,
    timezone: Option<String>,
    custom_grouping: Option<String>,
    custom_intervalle_min: Option<usize>,
    custom_intervalle_max: Option<usize>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ResultatStatistiquesSenseurRow {
    #[serde(
    serialize_with = "epochseconds::serialize",
    deserialize_with = "chrono_datetime_as_bson_datetime::deserialize"
    )]
    heure: ChronoDateTime<Utc>,
    min: Option<f64>,
    max: Option<f64>,
    avg: Option<f64>,
}

async fn requete_get_statistiques_senseur<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireSenseursPassifs)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao
{
    debug!("requete_get_statistiques_senseur Consommer requete : {:?}", & m.message);
    let requete: RequeteGetStatistiquesSenseur = deser_message_buffer!(m.message);

    let user_id = match m.certificat.get_user_id()? {
        Some(inner) => inner,
        None => {
            // let reponse = json!({"ok": false, "err": "user_id manquant"});
            // return Ok(Some(middleware.formatter_reponse(&reponse, None)?));
            return Ok(Some(middleware.reponse_err(None, None, Some("user_id manquant"))?))
        }
    };

    // Determiner timezone
    const UTC_STR: &str = "UTC";
    let tz: Tz = match requete.timezone.as_ref() {
        Some(tz) => {
            tz.parse().unwrap_or_else(|e| {
                info!("requete_get_statistiques_senseur Mauvais timezone, defaulting a UTC : {:?}", e);
                UTC_STR.parse().expect("utc")
            })
        },
        None => UTC_STR.parse().expect("utc")
    };

    debug!("requete_get_statistiques_senseur Timezone {:?} - grouping {:?}", tz, requete.custom_grouping);

    let collection = middleware.get_collection(COLLECTIONS_SENSEURS_HORAIRE)?;

    let reponse = match requete.custom_grouping.as_ref() {
        Some(grouping) => {
            let min_date = match requete.custom_intervalle_min {
                Some(d) => d,
                None => Err(format!("rapport_custom custom_intervalle_min manquant"))?
            };
            let min_date: ChronoDateTime<Utc> = ChronoDateTime::from_utc(NaiveDateTime::from_timestamp(min_date as i64, 0), Utc);
            let mut intervalle_heures = doc! {"$gte": min_date.timestamp()};
            let max_date = match requete.custom_intervalle_max {
                Some(inner) => {
                    Some(ChronoDateTime::from_utc(NaiveDateTime::from_timestamp(inner as i64, 0), Utc))
                },
                None => None
            };

            // Query
            let resultat = query_aggregate(
                middleware, user_id.as_str(), &requete, grouping.as_str(), &tz, min_date, max_date).await?;

            json!({
                "ok": true,
                "custom": resultat,
            })
        },
        None => {
            let periode72h = {
                let min_date = Utc::now() - Duration::days(3);
                query_aggregate(middleware, user_id.as_str(), &requete, "heures", &tz, min_date, None).await?
            };

            let periode31j = {
                let min_date = Utc::now() - Duration::days(31);
                let min_date = jour_juste(&min_date);
                query_aggregate(middleware, user_id.as_str(), &requete, "jours", &tz, min_date, None).await?
            };

            json!({
                "ok": true,
                "periode72h": periode72h,
                "periode31j": periode31j,
            })
        },
    };

    debug!("requete_get_statistiques_senseur Reponse : {:?}", reponse);

    Ok(Some(middleware.build_reponse(&reponse)?.0))
}

#[derive(Deserialize)]
struct RequeteGetConfigurationUsager {
    user_id: Option<String>
}

#[derive(Deserialize)]
struct RowCollectionUsager {
    user_id: String,
    timezone: Option<String>,
}

impl RowCollectionUsager {
    fn default<S>(user_id: S) -> Self
        where S: ToString
    {
        Self {
            user_id: user_id.to_string(),
            timezone: None,
        }
    }
}

#[derive(Serialize)]
struct ReponseGetConfigurationUsager {
    ok: bool,
    user_id: String,
    timezone: Option<String>,
    geoposition: Option<GeopositionAppareil>,
}

impl From<RowCollectionUsager> for ReponseGetConfigurationUsager {
    fn from(value: RowCollectionUsager) -> Self {
        Self {
            ok: true,
            user_id: value.user_id,
            timezone: value.timezone,
            geoposition: None,
        }
    }
}

async fn requete_get_configuration_usager<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireSenseursPassifs)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao
{
    debug!("requete_get_configuration_usager Consommer requete : {:?}", & m.message);
    let requete: RequeteGetConfigurationUsager = deser_message_buffer!(m.message);

    let user_id = match m.certificat.get_user_id()? {
        Some(inner) => inner,
        None => {
            if ! m.certificat.verifier_exchanges(vec![Securite::L2Prive])? {
                // let reponse = json!({"ok": false, "err": "user_id manquant (1)"});
                // return Ok(Some(middleware.formatter_reponse(&reponse, None)?));
                return Ok(Some(middleware.reponse_err(None, None, Some("user_id manquant (1)"))?))
            }
            match requete.user_id {
                Some(inner) => inner,
                None => {
                    // let reponse = json!({"ok": false, "err": "user_id manquant (2)"});
                    // return Ok(Some(middleware.formatter_reponse(&reponse, None)?));
                    return Ok(Some(middleware.reponse_err(None, None, Some("user_id manquant (2)"))?))
                }
            }
        }
    };

    let collection = middleware.get_collection_typed::<RowCollectionUsager>(COLLECTIONS_USAGER)?;
    let filtre = doc! { CHAMP_USER_ID: &user_id };
    let configuration_usager = match collection.find_one(filtre, None).await? {
        Some(inner) => inner,
        None => RowCollectionUsager::default(&user_id)
    };

    let reponse = ReponseGetConfigurationUsager::from(configuration_usager);

    Ok(Some(middleware.build_reponse(&reponse)?.0))
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

async fn requete_get_timezone_appareil<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireSenseursPassifs)
                                          -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao
{
    debug!("requete_get_timezone_appareil Consommer requete : {:?}", & m.message);
    let requete: RequeteGetTimezoneAppareil = deser_message_buffer!(m.message);

    let appareil = {
        // Charger appareil
        let collection_appareil =
            middleware.get_collection_typed::<InformationAppareil>(COLLECTIONS_APPAREILS)?;
        let filtre = doc! {CHAMP_USER_ID: &requete.user_id, CHAMP_UUID_APPAREIL: &requete.uuid_appareil};
        match collection_appareil.find_one(filtre, None).await? {
            Some(inner) => inner,
            None => {
                let reponse = ReponseGetTimezoneAppareil{
                    ok: false, err: Some("Appareil inconnu".to_string()), timezone: None, geoposition: None};
                return Ok(Some(middleware.build_reponse(reponse)?.0))
            }
        }
    };

    let (timezone, geoposition) = match appareil.configuration {
        Some(configuration) => (configuration.timezone, configuration.geoposition),
        None => (None, None)
    };

    let timezone = match timezone {
        Some(inner) => Some(inner),
        None => {
            // Tenter de charger la timezone du compte usager
            let collection = middleware.get_collection_typed::<RowCollectionUsager>(COLLECTIONS_USAGER)?;
            let filtre = doc! { CHAMP_USER_ID: &requete.user_id };
            match collection.find_one(filtre, None).await? {
                Some(inner) => inner.timezone,
                None => None
            }
        }
    };

    let reponse = ReponseGetTimezoneAppareil {
        ok: true, err: None, timezone, geoposition
    };
    Ok(Some(middleware.build_reponse(reponse)?.0))
}

async fn query_aggregate<M>(
    middleware: &M, user_id: &str, requete: &RequeteGetStatistiquesSenseur, grouping: &str,
    tz: &Tz, min_date: ChronoDateTime<Utc>, max_date: Option<ChronoDateTime<Utc>>
)
    -> Result<Vec<ResultatStatistiquesSenseurRow>, Error>
    where M: GenerateurMessages + MongoDao
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

    debug!("query_aggregate Requete pipeline\n{}", serde_json::to_string_pretty(&pipeline)?);

    let mut reponse = Vec::with_capacity(100);
    let collection = middleware.get_collection(COLLECTIONS_SENSEURS_HORAIRE)?;
    let mut result = collection.aggregate(pipeline, None).await?;
    while let Some(d) = result.next().await {
        let row: ResultatStatistiquesSenseurRow = convertir_bson_deserializable(d?)?;
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

fn jour_juste(date: &ChronoDateTime<Utc>) -> ChronoDateTime<Utc> {
    date.with_hour(0).expect("with_minutes")
        .with_minute(0).expect("with_minutes")
        .with_second(0).expect("with_seconds")
        .with_nanosecond(0).expect("with_nanosecond")
}
