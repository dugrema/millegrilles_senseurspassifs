use std::error::Error;
use log::{debug, warn};
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::middleware::EmetteurNotificationsTrait;
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::recepteur_messages::MessageValideAction;
use millegrilles_common_rust::verificateur::VerificateurMessage;
use millegrilles_common_rust::serde::Deserialize;

use crate::common::*;
use millegrilles_common_rust::constantes::*;
use crate::senseurspassifs::GestionnaireSenseursPassifs;

#[derive(Debug, Deserialize)]
struct EvenementPresenceAppareil {
    uuid_appareil: String,
    user_id: String,
    deconnecte: Option<bool>,
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
        warn!("evenement_appareil_presence Evenement presenceAppareil recu sans role {}, SKIP", ROLE_RELAI_NOM);
        return Ok(())
    }

    let filtre = doc!{
        CHAMP_UUID_APPAREIL: &evenement.uuid_appareil,
        CHAMP_USER_ID: &evenement.user_id,
    };
    let deconnecte = match evenement.deconnecte.as_ref() {Some(b)=>b.to_owned(), None => false};
    let set_ops = doc!{CHAMP_CONNECTE: !deconnecte};
    let ops = doc!{
        "$set": set_ops,
        "$currentDate": {CHAMP_MODIFICATION: true, CHAMP_MAJ_CONNEXION: true}
    };
    let collection = middleware.get_collection(COLLECTIONS_APPAREILS)?;
    collection.update_one(filtre, ops, None).await?;

    Ok(())
}
