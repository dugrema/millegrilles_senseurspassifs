use std::error::Error;
use log::{debug, error};
use millegrilles_common_rust::bson::doc;

use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
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
    match message.verifier_exchanges(vec![Securite::L2Prive, Securite::L3Protege, Securite::L4Secure]) {
        true => Ok(()),
        false => {
            match message.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
                true => Ok(()),
                false => Err(format!("senseurspassifs.consommer_requete Autorisation invalide (pas d'un exchange reconnu) : {}", message.routing_key))
            }
        },
    }?;

    match message.domaine.as_str() {
        DOMAINE_NOM => {
            match message.action.as_str() {
                REQUETE_GET_APPAREILS_USAGER => requete_appareils_usager(middleware, message, gestionnaire).await,
                REQUETE_LISTE_NOEUDS => requete_liste_noeuds(middleware, message, gestionnaire).await,
                REQUETE_LISTE_SENSEURS_PAR_UUID => requete_liste_senseurs_par_uuid(middleware, message, gestionnaire).await,
                REQUETE_LISTE_SENSEURS_NOEUD => requete_liste_senseurs_pour_noeud(middleware, message, gestionnaire).await,
                REQUETE_GET_NOEUD => requete_get_noeud(middleware, message, gestionnaire).await,
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

    todo!("Fix me");

    // let noeuds = {
    //     let filtre = doc! { };
    //     let projection = doc! {
    //         CHAMP_INSTANCE_ID: 1,
    //         "securite": 1,
    //         CHAMP_MODIFICATION: 1,
    //         "descriptif": 1,
    //     };
    //     let opts = FindOptions::builder().projection(projection).build();
    //     let collection = middleware.get_collection(COLLECTIONS_INSTANCES)?;
    //     let mut curseur = collection.find(filtre, opts).await?;
    //
    //     let mut noeuds = Vec::new();
    //     while let Some(d) = curseur.next().await {
    //         let noeud: TransactionMajNoeud = convertir_bson_deserializable(d?)?;
    //         noeuds.push(noeud);
    //     }
    //
    //     noeuds
    // };
    //
    // let reponse = json!({ "ok": true, "instances": noeuds, "instance_id": &gestionnaire.instance_id });
    // Ok(Some(middleware.formatter_reponse(&reponse, None)?))
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
struct RequeteSenseursParUuid {
    uuid_senseurs: Vec<String>,
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
struct RequeteSenseursPourNoeud {
    instance_id: String,
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
struct RequeteGetNoeud {
    instance_id: String
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
struct RequeteGetAppareilsEnAttente {
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ReponseGetAppareilsEnAttente {
    appareils: Vec<DocAppareil>,
}
