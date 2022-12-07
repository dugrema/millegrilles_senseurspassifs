use std::collections::{BTreeMap, HashMap};
use millegrilles_common_rust::formatteur_messages::DateEpochSeconds;
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::serde_json::Value;

pub const DOMAINE_NOM: &str = "SenseursPassifs";
pub const ROLE_RELAI_NOM: &str = "senseurspassifs_relai";

pub const REQUETE_GET_APPAREILS_USAGER: &str = "getAppareilsUsager";
pub const REQUETE_LISTE_NOEUDS: &str = "listeNoeuds";
pub const REQUETE_GET_NOEUD: &str = "getNoeud";
pub const REQUETE_LISTE_SENSEURS_PAR_UUID: &str = "listeSenseursParUuid";
pub const REQUETE_LISTE_SENSEURS_NOEUD: &str = "listeSenseursPourNoeud";
pub const REQUETE_GET_APPAREILS_EN_ATTENTE: &str = "getAppareilsEnAttente";
pub const REQUETE_GET_APPAREIL_DISPLAY_CONFIGURATION: &str = "getAppareilDisplayConfiguration";

pub const EVENEMENT_LECTURE: &str = "lecture";
pub const EVENEMENT_LECTURE_CONFIRMEE: &str = "lectureConfirmee";

pub const COMMANDE_INSCRIRE_APPAREIL: &str = "inscrireAppareil";
pub const COMMANDE_CHALLENGE_APPAREIL: &str = "challengeAppareil";
pub const COMMANDE_SIGNER_APPAREIL: &str = "signerAppareil";

pub const TRANSACTION_LECTURE: &str = "lecture";
pub const TRANSACTION_MAJ_SENSEUR: &str = "majSenseur";
pub const TRANSACTION_MAJ_NOEUD: &str = "majNoeud";
pub const TRANSACTION_SUPPRESSION_SENSEUR: &str = "suppressionSenseur";
pub const TRANSACTION_MAJ_APPAREIL: &str = "majAppareil";

//const CHAMP_INSTANCE_ID: &str = "instance_id";
pub const CHAMP_INSTANCE_ID: &str = "instance_id";
pub const CHAMP_UUID_SENSEUR: &str = "uuid_senseur";
pub const CHAMP_UUID_APPAREIL: &str = "uuid_appareil";
pub const CHAMP_SENSEURS: &str = "senseurs";
pub const CHAMP_USER_ID: &str = "user_id";

pub const COLLECTIONS_NOM: &str = "SenseursPassifs";
pub const COLLECTIONS_INSTANCES: &str = "SenseursPassifs/instances";
pub const COLLECTIONS_LECTURES: &str = "SenseursPassifs/lectures";
pub const COLLECTIONS_APPAREILS: &str = "SenseursPassifs/appareils";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionMajNoeud {
    pub instance_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub descriptif: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub securite: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lcd_actif: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lcd_affichage: Option<Vec<LigneAffichageLcd>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LigneAffichageLcd {
    pub uuid: String,
    pub appareil: String,
    pub affichage: String,
}

impl TransactionMajNoeud {
    pub fn new<S>(uuid_noeud: S)  -> Self
        where S: Into<String>
    {
        TransactionMajNoeud {
            instance_id: uuid_noeud.into(),
            descriptif: None,
            securite: None,
            lcd_actif: None,
            lcd_affichage: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LectureTransaction {
    pub timestamp: DateEpochSeconds,
    pub valeur: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InformationAppareil {
    pub uuid_appareil: String,
    pub instance_id: String,
    pub user_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub descriptif: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub senseurs: Option<BTreeMap<String, LectureSenseur>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derniere_lecture: Option<DateEpochSeconds>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub configuration: Option<ConfigurationAppareil>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DocAppareil {
    pub uuid_appareil: String,
    pub instance_id: String,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derniere_lecture: Option<DateEpochSeconds>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub configuration: Option<ConfigurationAppareil>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub displays: Option<Vec<ParamsDisplay>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LectureAppareil {
    pub lectures_senseurs: HashMap<String, LectureSenseur>,
    pub displays: Option<Vec<ParamsDisplay>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParamsDisplay {
    pub name: String,
    pub format: String,
    pub height: Option<u16>,
    pub width: Option<u16>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LectureSenseur {
    pub timestamp: DateEpochSeconds,
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
    pub displays: Option<HashMap<String, ParametresDisplay>>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParametresDisplay {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lignes: Option<Vec<ParametresDisplayLigne>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub afficher_date_duree: Option<u16>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParametresDisplayLigne {
    pub masque: String,
    pub variable: Option<String>,
    pub duree: Option<u16>,
}
