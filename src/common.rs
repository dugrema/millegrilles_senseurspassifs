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
pub const REQUETE_GET_APPAREIL_PROGRAMMES_CONFIGURATION: &str = "getAppareilProgrammesConfiguration";
pub const REQUETE_GET_STATISTIQUES_SENSEUR: &str = "getStatistiquesSenseur";
pub const REQUETE_GET_CONFIGURATION_USAGER: &str = "getConfigurationUsager";

pub const EVENEMENT_LECTURE: &str = "lecture";
pub const EVENEMENT_LECTURE_CONFIRMEE: &str = "lectureConfirmee";
pub const EVENEMENT_MAJ_DISPLAYS: &str = "evenementMajDisplays";
pub const EVENEMENT_MAJ_PROGRAMMES: &str = "evenementMajProgrammes";
pub const EVENEMENT_PRESENCE_APPAREIL: &str = "presenceAppareil";

pub const COMMANDE_INSCRIRE_APPAREIL: &str = "inscrireAppareil";
pub const COMMANDE_CHALLENGE_APPAREIL: &str = "challengeAppareil";
pub const COMMANDE_SIGNER_APPAREIL: &str = "signerAppareil";
pub const COMMANDE_CONFIRMER_RELAI: &str = "confirmerRelai";

pub const TRANSACTION_LECTURE: &str = "lecture";
pub const TRANSACTION_MAJ_SENSEUR: &str = "majSenseur";
pub const TRANSACTION_MAJ_NOEUD: &str = "majNoeud";
pub const TRANSACTION_SUPPRESSION_SENSEUR: &str = "suppressionSenseur";
pub const TRANSACTION_INIT_APPAREIL: &str = "initAppareil";
pub const TRANSACTION_MAJ_APPAREIL: &str = "majAppareil";
pub const TRANSACTION_SENSEUR_HORAIRE: &str = "senseurHoraire";
pub const TRANSACTION_APPAREIL_SUPPRIMER: &str = "supprimerAppareil";
pub const TRANSACTION_APPAREIL_RESTAURER: &str = "restaurerAppareil";
pub const TRANSACTION_MAJ_CONFIGURATION_USAGER: &str = "majConfigurationUsager";

//const CHAMP_INSTANCE_ID: &str = "instance_id";
pub const CHAMP_INSTANCE_ID: &str = "instance_id";
pub const CHAMP_UUID_SENSEUR: &str = "uuid_senseur";
pub const CHAMP_UUID_APPAREIL: &str = "uuid_appareil";
pub const CHAMP_SENSEURS: &str = "senseurs";
pub const CHAMP_USER_ID: &str = "user_id";
pub const CHAMP_DERNIERE_LECTURE: &str = "derniere_lecture_dt";
pub const CHAMP_PRESENT: &str = "present";
pub const CHAMP_CONNECTE: &str = "connecte";
pub const CHAMP_MAJ_CONNEXION: &str = "maj_connexion";
pub const CHAMP_VERSION: &str = "version";
pub const CHAMP_NOTIFICATION_PRESENCE: &str = "notification_presence";
pub const CHAMP_DIRTY: &str = "dirty";
pub const CHAMP_PRESENTS: &str = "presents";
pub const CHAMP_ABSENTS: &str = "absents";
pub const CHAMP_LECTURES_DISPONIBLES: &str = "lectures_disponibles";
pub const CHAMP_SUPPRIME: &str = "supprime";

pub const COLLECTIONS_NOM: &str = "SenseursPassifs";
pub const COLLECTIONS_INSTANCES: &str = "SenseursPassifs/instances";
pub const COLLECTIONS_LECTURES: &str = "SenseursPassifs/lectures";
pub const COLLECTIONS_APPAREILS: &str = "SenseursPassifs/appareils";
pub const COLLECTIONS_SENSEURS_HORAIRE: &str = "SenseursPassifs/senseurs_horaire";
pub const COLLECTIONS_NOTIFICATIONS_USAGERS: &str = "SenseursPassifs/notifications_usagers";
pub const COLLECTIONS_RELAIS: &str = "SenseursPassifs/relais";
pub const COLLECTIONS_USAGER: &str = "SenseursPassifs/usager";

pub const INDEX_LECTURES_NOEUD: &str = "lectures_noeud";
pub const INDEX_LECTURES_SENSEURS: &str = "lectures_senseur";
pub const INDEX_LECTURES_HORAIRE: &str = "lectures_horaire";
pub const INDEX_LECTURES_HORAIRE_RAPPORT: &str = "lectures_horaire_rapport";
pub const INDEX_USER_APPAREILS: &str = "user_appareils";
pub const INDEX_APPAREILS_DERNIERE_LECTURE: &str = "appareils_derniere_lecture";
pub const INDEX_USER_NOTIFICATIONS: &str = "user_notifications_usager";
pub const INDEX_USER_APPAREIL_RELAIS: &str = "user_appareil_relais";

pub const CONST_APAREIL_LECTURE_TIMEOUT_SECS: i64 = 900;

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connecte: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

impl<'a> InformationAppareil{
    pub fn get_descriptif(&'a self) -> &'a str {
        match &self.configuration {
            Some(inner) => match &inner.descriptif {
                Some(inner) => inner.as_str(),
                None => self.uuid_appareil.as_str()
            },
            None => self.uuid_appareil.as_str()
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DocAppareil {
    pub uuid_appareil: String,
    pub instance_id: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub programmes: Option<HashMap<String, ProgrammeAppareil>>,

    /// Si true, indique qu'une transaction a ete produite (requis pour regeneration)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub persiste: Option<bool>,

    /// Liste de senseurs avec des lectures disponibles (historique)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lectures_disponibles: Option<Vec<String>>,

    /// Flag supprime (agit davantage comme "hide")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supprime: Option<bool>,

    /// Flag connecte (websocket)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connecte: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NotificationAppareil {
    pub programme_id: String,
    pub message: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LectureAppareil {
    pub lectures_senseurs: HashMap<String, LectureSenseur>,
    pub displays: Option<Vec<ParamsDisplay>>,
    pub notifications: Option<Vec<NotificationAppareil>>
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
    pub displays: Option<HashMap<String, ParametresDisplay>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub programmes: Option<HashMap<String, ProgrammeAppareil>>,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProgrammeAppareil {
    programme_id: String,
    class: String,
    descriptif: Option<String>,
    actif: Option<bool>,
    args: HashMap<String, Value>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionLectureHoraire {
    pub heure: DateEpochSeconds,
    pub user_id: String,
    pub uuid_appareil: String,
    pub senseur_id: String,
    pub lectures: Vec<LectureSenseur>,
    pub min: Option<f64>,
    pub max: Option<f64>,
    pub avg: Option<f64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DocumentNotificationUsager {
    pub user_id: String,
    pub presents: Option<Vec<String>>,
    pub absents: Option<Vec<String>>,
    pub cle_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NotificationAppareilUsager {
    pub user_id: String,
    pub uuid_appareil: String,
    pub notification: NotificationAppareil,
}
