use log::{debug, warn};

use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::middleware::EmetteurNotificationsTrait;
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::serde::{Serialize, Deserialize};
use millegrilles_common_rust::error::Error;

use crate::common::*;

use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::millegrilles_cryptographie::deser_message_buffer;
use millegrilles_common_rust::rabbitmq_dao::TypeMessageOut;
use millegrilles_common_rust::recepteur_messages::MessageValide;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::get_domaine_action;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use crate::domain_manager::SenseursPassifsDomainManager;
use crate::lectures::evenement_domaine_lecture;

pub async fn consommer_evenement<M>(middleware: &M, gestionnaire: &SenseursPassifsDomainManager, m: MessageValide)
                                    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("senseurspassifs.consommer_evenement Consommer evenement : {:?}", &m.type_message);

    // Autorisation : doit etre de niveau 2.prive, 3.protege ou 4.secure
    match m.certificat.verifier_exchanges(vec![Securite::L2Prive, Securite::L3Protege, Securite::L4Secure])? {
        true => Ok(()),
        false => Err(Error::Str("senseurspassifs.consommer_evenement: Evenement invalide (pas 2.prive, 3.protege ou 4.secure)")),
    }?;

    let (_, action) = get_domaine_action!(m.type_message);

    match action.as_str() {
        EVENEMENT_LECTURE => { evenement_domaine_lecture(middleware, &m, gestionnaire).await?; Ok(None) },
        EVENEMENT_PRESENCE_APPAREIL => { evenement_appareil_presence(middleware, &m).await?; Ok(None) },
        EVENEMENT_CEDULE => Ok(None),  // Obsolete, utiliser evenement ping
        _ => Err(format!("senseurspassifs.consommer_evenement: Mauvais type d'action pour une transaction : {}", action))?,
    }

    // debug!("consommer_evenement Consommer evenement : {:?}", &m.type_message);
    //
    // // Autorisation : doit etre de niveau 3.protege ou 4.secure
    // match m.certificat.verifier_exchanges(vec![Securite::L2Prive])? {
    //     true => Ok(()),
    //     false => Err(format!("events.consommer_evenement: Exchange evenement invalide (pas 2.prive)")),
    // }?;
    //
    // let action = {
    //     match &m.type_message {
    //         TypeMessageOut::Evenement(r) => r.action.clone(),
    //         _ => Err(CommonError::Str("events.consommer_evenement Mauvais type de message (pas evenement)"))?
    //     }
    // };
    //
    // match action.as_str() {
    //     // EVENEMENT_TRANSCODAGE_PROGRES => evenement_transcodage_progres(middleware, m).await,
    //     EVENEMENT_CEDULE => Ok(None),  // Obsolete, utiliser evenement ping
    //     _ => Err(format!("events.consommer_evenement: Mauvais type d'action pour un evenement : {}", action))?,
    // }
}


#[derive(Debug, Serialize, Deserialize)]
struct EvenementPresenceAppareil {
    uuid_appareil: String,
    user_id: String,
    version: Option<String>,
    deconnecte: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct EvenementPresenceAppareilUser {
    pub uuid_appareil: String,
    pub user_id: String,
    pub version: Option<String>,
    pub connecte: bool,
}

pub async fn evenement_appareil_presence<M>(middleware: &M, m: &MessageValide) -> Result<(), Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("evenement_appareil_presence Recu evenement {:?}", &m.message);
    let evenement: EvenementPresenceAppareil = deser_message_buffer!(m.message);
    debug!("Evenement mappe : {:?}", evenement);

    let certificat = m.certificat.as_ref();

    if ! certificat.verifier_exchanges(vec![Securite::L2Prive])? {
        warn!("evenement_appareil_presence Evenement presenceAppareil recu sans securite 2.prive, SKIP");
        return Ok(())
    }
    if ! certificat.verifier_roles_string(vec![ROLE_RELAI_NOM.to_string()])? {
        let extensions = certificat.get_extensions()?;
        warn!("evenement_appareil_presence Evenement presenceAppareil recu sans role {} (extensions: {:?}) SKIP", ROLE_RELAI_NOM, extensions);
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
        let routage = RoutageMessageAction::builder(DOMAINE_NOM, "presenceAppareil", vec![Securite::L2Prive])
            .partition(&evenement_reemis.user_id)
            .build();
        middleware.emettre_evenement(routage, &evenement_reemis).await?;
    }

    Ok(())
}
