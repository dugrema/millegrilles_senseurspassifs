use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::certificats::VerificateurPermissions;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::tracing::warn;
use millegrilles_common_rust::v3::facades::message_inbound::MessageValidated;
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::generateur_messages::RoutageMessageAction;
use crate::common::{COLLECTIONS_APPAREILS, ROLE_RELAI_NOM};
use crate::models::{EvenementPresenceAppareil, EvenementPresenceAppareilUser};
use crate::common::*;

pub const EVENEMENT_PRESENCE_APPAREIL: &str = "presenceAppareil";

pub async fn device_presence_event(
    mongo: &dyn MongoDao,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> {
    let evenement: EvenementPresenceAppareil = wrapper.message.deserialize()?;
    let certificate = wrapper.certificate.as_ref();

    if ! certificate.verifier_exchanges(vec![Securite::L2Prive])? {
        warn!("evenement_appareil_presence Evenement presenceAppareil recu sans securite 2.prive, SKIP");
        return Ok(())
    }

    if ! certificate.verifier_roles_string(vec![ROLE_RELAI_NOM.to_string()])? {
        let extensions = certificate.get_extensions()?;
        warn!(
            "evenement_appareil_presence Evenement presenceAppareil recu sans role {} (extensions: {:?}) SKIP",
            ROLE_RELAI_NOM,
            extensions
        );
        return Ok(())
    }

    // Update device in database
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
    let collection = mongo.get_collection(COLLECTIONS_APPAREILS)?;
    collection.update_one(filtre, ops).await?;

    // Re-emit the event for the affected user_id
    {
        let new_event = EvenementPresenceAppareilUser {
            uuid_appareil: evenement.uuid_appareil,
            user_id: evenement.user_id,
            version: evenement.version,
            connecte: !deconnecte
        };
        let routage = RoutageMessageAction::builder(
            DOMAINE_NOM,
            "presenceAppareil",
            vec![Securite::L2Prive]
        )
            .partition(&new_event.user_id)
            .build();
        outbound.emit_event(routage, &new_event).await?;
    }

    Ok(())
}
