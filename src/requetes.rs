use std::error::Error;
use log::{debug, error};
use millegrilles_common_rust::bson::{bson, doc};

use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chrono;
use millegrilles_common_rust::chrono::Utc;
use millegrilles_common_rust::formatteur_messages::MessageMilleGrille;
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, convertir_bson_value, filtrer_doc_id, MongoDao};
use millegrilles_common_rust::mongodb::options::{FindOneOptions, FindOptions};
use millegrilles_common_rust::recepteur_messages::MessageValideAction;
use millegrilles_common_rust::serde_json::{json, Value};
use millegrilles_common_rust::verificateur::VerificateurMessage;
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::serde::{Deserialize, Serialize};

use crate::senseurspassifs::GestionnaireSenseursPassifs;
use crate::common::*;

pub async fn consommer_requete<M>(middleware: &M, message: MessageValideAction, gestionnaire: &GestionnaireSenseursPassifs) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao + VerificateurMessage
{
    debug!("Consommer requete : {:?}", &message.message);

    // Autorisation : On accepte les requetes de 3.protege ou 4.secure
    let exchanges_ok = message.verifier_exchanges(vec![Securite::L2Prive, Securite::L3Protege, Securite::L4Secure]);
    let delegation_globale = message.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE);
    let user_id = message.get_user_id();

    if exchanges_ok || delegation_globale {
        match message.domaine.as_str() {
            DOMAINE_NOM => {
                match message.action.as_str() {
                    REQUETE_GET_APPAREILS_USAGER => requete_appareils_usager(middleware, message, gestionnaire).await,
                    REQUETE_GET_APPAREIL_DISPLAY_CONFIGURATION => requete_appareil_display_configuration(middleware, message, gestionnaire).await,
                    REQUETE_LISTE_NOEUDS => requete_liste_noeuds(middleware, message, gestionnaire).await,
                    REQUETE_LISTE_SENSEURS_PAR_UUID => requete_liste_senseurs_par_uuid(middleware, message, gestionnaire).await,
                    REQUETE_LISTE_SENSEURS_NOEUD => requete_liste_senseurs_pour_noeud(middleware, message, gestionnaire).await,
                    REQUETE_GET_NOEUD => requete_get_noeud(middleware, message, gestionnaire).await,
                    REQUETE_GET_APPAREILS_EN_ATTENTE => requete_get_appareils_en_attente(middleware, message, gestionnaire).await,
                    REQUETE_GET_STATISTIQUES_SENSEUR => requete_get_statistiques_senseur(middleware, message, gestionnaire).await,
                    _ => {
                        error!("Message requete/action inconnue : '{}'. Message dropped.", message.action);
                        Ok(None)
                    },
                }
            },
            _ => {
                error!("Message requete/domaine inconnu : '{}'. Message dropped.", message.domaine);
                Ok(None)
            },
        }
    } else if user_id.is_some() {
        match message.domaine.as_str() {
            DOMAINE_NOM => {
                match message.action.as_str() {
                    REQUETE_GET_APPAREILS_USAGER => requete_appareils_usager(middleware, message, gestionnaire).await,
                    REQUETE_GET_APPAREIL_DISPLAY_CONFIGURATION => requete_appareil_display_configuration(middleware, message, gestionnaire).await,
                    REQUETE_GET_APPAREILS_EN_ATTENTE => requete_get_appareils_en_attente(middleware, message, gestionnaire).await,
                    _ => {
                        error!("Message requete/action inconnue : '{}'. Message dropped.", message.action);
                        Ok(None)
                    },
                }
            },
            _ => {
                error!("Message requete/domaine inconnu : '{}'. Message dropped.", message.domaine);
                Ok(None)
            },
        }
    } else {
        error!("Message autorisation refusee : '{}'. Message dropped.", message.domaine);
        Ok(None)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteAppareilsUsager {
}

async fn requete_appareils_usager<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireSenseursPassifs)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
{
    debug!("requete_appareils_usager Consommer requete : {:?}", & m.message);
    let requete: RequeteAppareilsUsager = m.message.get_msg().map_contenu(None)?;

    let user_id = match m.get_user_id() {
        Some(inner) => inner,
        None => {
            let reponse = json!({"ok": false, "err": "user_id manquant"});
            return Ok(Some(middleware.formatter_reponse(&reponse, None)?));
        }
    };

    let appareils = {
        let mut appareils = Vec::new();

        let filtre = doc! { CHAMP_USER_ID: user_id };

        let projection = doc! {
            CHAMP_UUID_APPAREIL: 1,
            CHAMP_INSTANCE_ID: 1,
            "derniere_lecture": 1,
            "descriptif": 1,
            "senseurs": 1,
            "configuration": 1,
            "displays": 1,
        };

        let collection = middleware.get_collection(COLLECTIONS_APPAREILS)?;

        let opts = FindOptions::builder()
            .projection(projection)
            .limit(100)
            .build();
        let mut curseur = collection.find(filtre, opts).await?;

        while let Some(d) = curseur.next().await {
            let appareil: DocAppareil = convertir_bson_deserializable(d?)?;
            appareils.push(appareil);
        }

        appareils
    };

    let reponse = json!({ "ok": true, "appareils": appareils, "instance_id": &gestionnaire.instance_id });
    Ok(Some(middleware.formatter_reponse(&reponse, None)?))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteAppareilsDisplayConfiguration {
    // uuid_appareil: String,  // Extrait du certificat, comme user_id
}

async fn requete_appareil_display_configuration<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireSenseursPassifs)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
{
    debug!("requete_appareil_display_configuration Consommer requete : {:?}", & m.message);
    let requete: RequeteAppareilsDisplayConfiguration = m.message.get_msg().map_contenu(None)?;

    // Extraire user_id, uuid_appareil du certificat
    let (user_id, uuid_appareil) = match m.message.certificat {
        Some(c) => {
            let user_id = match c.get_user_id()? {
                Some(u) => u.to_owned(),
                None => Err(format!("EvenementLecture Evenement de lecture user_id manquant du certificat"))?
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

    let display_configuration = {
        let filtre = doc! { CHAMP_USER_ID: user_id, CHAMP_UUID_APPAREIL: uuid_appareil };

        let projection = doc! {
            CHAMP_UUID_APPAREIL: 1,
            CHAMP_INSTANCE_ID: 1,
            "derniere_lecture": 1,
            "configuration.displays": 1,
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
                let reponse = json!({"ok": false, "err": "appareil inconnu"});
                return Ok(Some(middleware.formatter_reponse(&reponse, None)?));
            }
        }
    };

    let reponse = json!({ "ok": true, "display_configuration": display_configuration });
    Ok(Some(middleware.formatter_reponse(&reponse, None)?))
}

async fn requete_liste_noeuds<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireSenseursPassifs)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
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
    Ok(Some(middleware.formatter_reponse(&reponse, None)?))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteSenseursParUuid {
    uuid_senseurs: Vec<String>,
}

async fn requete_liste_senseurs_par_uuid<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireSenseursPassifs)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
{
    debug!("requete_liste_senseurs_par_uuid Consommer requete : {:?}", & m.message);
    let requete: RequeteSenseursParUuid = m.message.get_msg().map_contenu(None)?;

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
    let reponse_formattee = middleware.formatter_reponse(&reponse, None)?;
    debug!("Reponse formattee : {:?}", reponse_formattee);
    Ok(Some(reponse_formattee))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteSenseursPourNoeud {
    instance_id: String,
}

async fn requete_liste_senseurs_pour_noeud<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireSenseursPassifs)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
{
    debug!("requete_liste_senseurs_pour_noeud Consommer requete : {:?}", & m.message);
    let requete: RequeteSenseursPourNoeud = m.message.get_msg().map_contenu(None)?;

    let senseurs = {
        let filtre = doc! { CHAMP_INSTANCE_ID: &requete.instance_id };
        let projection = doc! {
            CHAMP_UUID_SENSEUR: 1,
            CHAMP_INSTANCE_ID: 1,
            "derniere_lecture": 1,
            CHAMP_SENSEURS: 1,
            "securite": 1,
            "descriptif": 1,
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
    let reponse_formattee = middleware.formatter_reponse(&reponse, None)?;
    debug!("Reponse formattee : {:?}", reponse_formattee);
    Ok(Some(reponse_formattee))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteGetNoeud {
    instance_id: String
}

async fn requete_get_noeud<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireSenseursPassifs)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
{
    debug!("requete_get_noeud Consommer requete : {:?}", & m.message);
    let requete: RequeteGetNoeud = m.message.get_msg().map_contenu(None)?;

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

    Ok(Some(middleware.formatter_reponse(&reponse, None)?))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteGetAppareilsEnAttente {
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ReponseGetAppareilsEnAttente {
    appareils: Vec<DocAppareil>,
}

async fn requete_get_appareils_en_attente<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireSenseursPassifs)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
{
    debug!("requete_get_appareils_en_attente Consommer requete : {:?}", & m.message);
    let requete: RequeteGetAppareilsEnAttente = m.message.get_msg().map_contenu(None)?;

    let user_id = match m.get_user_id() {
        Some(inner) => inner,
        None => {
            let reponse = json!({"ok": false, "err": "user_id manquant"});
            return Ok(Some(middleware.formatter_reponse(&reponse, None)?));
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

    Ok(Some(middleware.formatter_reponse(&reponse, None)?))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteGetStatistiquesSenseur {
    uuid_appareil: String,
    senseur_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ResultatStatistiquesSenseurRow {
    heure: usize,
    min: Option<f64>,
    max: Option<f64>,
    avg: Option<f64>,
}

async fn requete_get_statistiques_senseur<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireSenseursPassifs)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
{
    debug!("requete_get_statistiques_senseur Consommer requete : {:?}", & m.message);
    let requete: RequeteGetStatistiquesSenseur = m.message.get_msg().map_contenu(None)?;

    let user_id = match m.get_user_id() {
        Some(inner) => inner,
        None => {
            let reponse = json!({"ok": false, "err": "user_id manquant"});
            return Ok(Some(middleware.formatter_reponse(&reponse, None)?));
        }
    };

    let collection = middleware.get_collection(COLLECTIONS_SENSEURS_HORAIRE)?;

    let periode72h = {
        let min_date = Utc::now() - chrono::Duration::days(3);

        let filtre = doc! {
            "user_id": &user_id,
            "uuid_appareil": &requete.uuid_appareil,
            "senseur_id": &requete.senseur_id,
            "heure": {"$gte": min_date.timestamp()}
        };

        let pipeline = vec![
            doc! { "$match": filtre },
            doc! { "$project": {"heure": 1, "avg": 1, "min": 1, "max": 1} },
            doc! { "$sort": {"heure": 1} }
        ];

        let mut reponse = Vec::new();
        let mut result = collection.aggregate(pipeline, None).await?;
        while let Some(d) = result.next().await {
            let row: ResultatStatistiquesSenseurRow = convertir_bson_deserializable(d?)?;
            reponse.push(row);
        }

        reponse
    };

    let periode31j = "31j";

    let reponse = json!({
        "ok": true,
        "periode72h": periode72h,
        "periode31j": periode31j,
    });

    debug!("requete_get_statistiques_senseur Reponse : {:?}", reponse);

    Ok(Some(middleware.formatter_reponse(&reponse, None)?))
}
