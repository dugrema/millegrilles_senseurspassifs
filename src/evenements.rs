use std::error::Error;
use log::{debug, warn};
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::middleware::EmetteurNotificationsTrait;
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::recepteur_messages::MessageValideAction;
use millegrilles_common_rust::verificateur::VerificateurMessage;
use millegrilles_common_rust::serde::{Serialize, Deserialize};

use crate::common::*;
use millegrilles_common_rust::constantes::*;
use crate::senseurspassifs::GestionnaireSenseursPassifs;

#[derive(Debug, Serialize, Deserialize)]
struct EvenementPresenceAppareil {
    uuid_appareil: String,
    user_id: String,
    version: Option<String>,
    deconnecte: Option<bool>,
}

#[derive(Debug, Serialize)]
struct EvenementPresenceAppareilUser {
    uuid_appareil: String,
    user_id: String,
    version: Option<String>,
    connecte: bool,
}

pub async fn evenement_appareil_presence<M>(middleware: &M, m: &MessageValideAction, gestionnaire: &GestionnaireSenseursPassifs) -> Result<(), Box<dyn Error>>
    where M: ValidateurX509 + VerificateurMessage + GenerateurMessages + MongoDao + EmetteurNotificationsTrait
{
    debug!("evenement_appareil_presence Recu evenement {:?}", &m.message);
    let evenement: EvenementPresenceAppareil = m.message.get_msg().map_contenu()?;
    debug!("Evenement mappe : {:?}", evenement);

    let certificat = match m.message.certificat.as_ref() {
        Some(inner) => inner.as_ref(),
        None => Err(format!("evenement_appareil_presence Erreur chargement certificat (absent)"))?
    };

    if ! certificat.verifier_exchanges(vec![Securite::L2Prive]) {
        warn!("evenement_appareil_presence Evenement presenceAppareil recu sans securite 2.prive, SKIP");
        return Ok(())
    }
    if ! certificat.verifier_roles_string(vec![ROLE_RELAI_NOM.to_string()]) {
        warn!("evenement_appareil_presence Evenement presenceAppareil recu sans role {} (roles: {:?}) SKIP", ROLE_RELAI_NOM, certificat.get_roles());
        return Ok(())
    }

    let filtre = doc!{
        CHAMP_UUID_APPAREIL: &evenement.uuid_appareil,
        CHAMP_USER_ID: &evenement.user_id,
    };
    let deconnecte = match evenement.deconnecte.as_ref() {Some(b)=>b.to_owned(), None => false};
    let set_ops = doc!{CHAMP_CONNECTE: !deconnecte, CHAMP_VERSION: evenement.version.as_ref()};
    let ops = doc!{
        "$set": set_ops,
        "$currentDate": {CHAMP_MODIFICATION: true, CHAMP_MAJ_CONNEXION: true}
    };
    let collection = middleware.get_collection(COLLECTIONS_APPAREILS)?;
    collection.update_one(filtre, ops, None).await?;

    // Re-emettre l'evenement pour le userId
    {
        let evenement_reemis = EvenementPresenceAppareilUser {
            uuid_appareil: evenement.uuid_appareil,
            user_id: evenement.user_id,
            version: evenement.version,
            connecte: !deconnecte
        };
        let routage = RoutageMessageAction::builder(DOMAINE_NOM, "presenceAppareil")
            .partition(&evenement_reemis.user_id)
            .exchanges(vec![Securite::L2Prive])
            .build();
        middleware.emettre_evenement(routage, &evenement_reemis).await?;
    }

    Ok(())
}
