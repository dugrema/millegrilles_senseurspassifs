use crate::common::*;
use crate::flow::events::device_presence_event;
use crate::flow::transactions::{SenseursPassifsTransactionService, TRANSACTION_APPAREIL_RESTAURER, TRANSACTION_APPAREIL_SUPPRIMER, TRANSACTION_INIT_APPAREIL, TRANSACTION_MAJ_APPAREIL, TRANSACTION_MAJ_CONFIGURATION_USAGER, TRANSACTION_MAJ_NOEUD, TRANSACTION_MAJ_SENSEUR, TRANSACTION_SAUVEGARDER_PROGRAMME, TRANSACTION_SHOW_HIDE_SENSOR, TRANSACTION_SUPPRESSION_SENSEUR};
use crate::models::{CommandeChallengeAppareil, CommandeInscrireAppareil, CommandeSignerAppareil, DocAppareil, EvenementPresenceAppareilUser, ReponseCertificat, TransactionInitialiserAppareil, TransactionMajAppareil, TransactionShowHideSensor};
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::certificats::VerificateurPermissions;
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::generateur_messages::RoutageMessageAction;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::optionepochseconds;
use millegrilles_common_rust::mongo_dao::{MongoDao, MongoDaoTyped};
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::serde_json::json;
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::tracing::{debug, error, info, warn};
use millegrilles_common_rust::v3::facades::message_inbound::MessageValidated;
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;
use millegrilles_common_rust::v3::models::ErrorMessage;
use millegrilles_common_rust::v3::{BackupService, PkiService, PresenceService};
use millegrilles_common_rust::{bson, serde_json};
use millegrilles_common_rust::common_messages::BackupEvent;
use crate::external::mongo::COLLECTION_NAME_REDOLOG;

pub const COMMANDE_INSCRIRE_APPAREIL: &str = "inscrireAppareil";
pub const COMMANDE_CHALLENGE_APPAREIL: &str = "challengeAppareil";
pub const COMMANDE_SIGNER_APPAREIL: &str = "signerAppareil";
pub const COMMANDE_CONFIRMER_RELAI: &str = "confirmerRelai";
pub const COMMANDE_RESET_CERTIFICATS: &str = "resetCertificatsAppareils";
pub const COMMAND_DISCONNECT_RELAY: &str = "disconnectRelay";

pub async fn process_command<M>(
    pki: &dyn PkiService,
    mongo: &M,
    outbound: &MessageOutboundFacade,
    transaction: &SenseursPassifsTransactionService,
    wrapper: MessageValidated
) -> Result<(), CommonError> where M: MongoDaoTyped {
    let action = match wrapper.get_routing_action() {
        Some(action) => action,
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err("No action provided in command")).await
    };

    match action {
        COMMANDE_INSCRIRE_APPAREIL => register_device_command(mongo, outbound, wrapper).await,
        COMMANDE_CHALLENGE_APPAREIL => device_challenge_command(mongo, outbound, wrapper).await,
        COMMANDE_SIGNER_APPAREIL => sign_device_command(pki, mongo, outbound, transaction, wrapper).await,
        COMMANDE_CONFIRMER_RELAI => confirm_relai(mongo, outbound, wrapper).await,
        COMMAND_DISCONNECT_RELAY => disconnect_relay_command(mongo, outbound, wrapper).await,
        EVENEMENT_PRESENCE_APPAREIL => device_presence_event(mongo, outbound, wrapper).await,

        // Obsolete commands
        COMMANDE_RESET_CERTIFICATS => outbound.respond(wrapper.delivery_info, ErrorMessage::err("resetCertificatsAppareils command is obsolete")).await,
        _ => {
            info!("Unknown action {} for process_command, skipping", action);
            Ok(())
        }
    }
}

/// Process the command part of the transaction (checks, validations, volatile updates),
/// calls transaction processor and then handles responses and emits events.
pub async fn process_transaction<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    transaction: &SenseursPassifsTransactionService,
    wrapper: MessageValidated
) -> Result<(), CommonError> where M: MongoDaoTyped {
    let action = match wrapper.get_routing_action() {
        Some(action) => action,
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err("No action provided in command")).await
    };
    match action {
        TRANSACTION_MAJ_APPAREIL => update_device_command(mongo, outbound, transaction, wrapper).await,
        TRANSACTION_SHOW_HIDE_SENSOR => show_hide_sensor_command(mongo, outbound, transaction, wrapper).await,

        // Obsolete commands (legacy transactions)
        TRANSACTION_MAJ_SENSEUR => outbound.respond(wrapper.delivery_info, ErrorMessage::err("majSenseur is obsolete")).await,
        TRANSACTION_MAJ_NOEUD => outbound.respond(wrapper.delivery_info, ErrorMessage::err("majNoeud is obsolete")).await,
        TRANSACTION_SUPPRESSION_SENSEUR => outbound.respond(wrapper.delivery_info, ErrorMessage::err("suppressionSenseur is obsolete")).await,
        TRANSACTION_SAUVEGARDER_PROGRAMME => outbound.respond(wrapper.delivery_info, ErrorMessage::err("sauvegarderProgramme is obsolete")).await,
        TRANSACTION_APPAREIL_SUPPRIMER => outbound.respond(wrapper.delivery_info, ErrorMessage::err("supprimerAppareil is obsolete")).await,
        TRANSACTION_APPAREIL_RESTAURER => outbound.respond(wrapper.delivery_info, ErrorMessage::err("restaurerAppareil is obsolete")).await,
        TRANSACTION_MAJ_CONFIGURATION_USAGER => outbound.respond(wrapper.delivery_info, ErrorMessage::err("majConfigurationUsager is obsolete")).await,
        _ => {
            info!("Unknown action {} for process_transaction, skipping", action);
            Ok(())
        }
    }
}

pub async fn process_backup(
    outbound: &MessageOutboundFacade,
    backup: &dyn BackupService,
    wrapper: MessageValidated
) -> Result<(), CommonError> {
    let action = match wrapper.get_routing_action() {
        Some(action) => action,
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err("No action provided in command")).await
    };
    match action {
        COMMANDE_DECLENCHER_BACKUP => trigger_complete_backup(outbound, backup, wrapper).await,
        COMMANDE_REGENERER => {
            let response = ErrorMessage {
                ok: false,
                code: Some(1),
                err: Some("Unsupported command through web interface. Use the CLI (provided script).".to_string())
            };
            outbound.respond(wrapper.delivery_info, response).await
        }
        _ => {
            warn!("process_backup_messages (CA) Unsupported command type: {}", action);
            let response = ErrorMessage { ok: false, code: Some(404), err: Some("Unsupported command".to_string()) };
            outbound.respond(wrapper.delivery_info, response).await.ok();
            Err(CommonError::Str("Bad message, unsupported action type"))
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CommandeConfirmerRelai {
    fingerprint: String,
    #[serde(default, with="optionepochseconds")]
    expiration: Option<DateTime<Utc>>,
}

async fn confirm_relai(
    mongo: &dyn MongoDao,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> {
    let commande: CommandeConfirmerRelai = wrapper.message.deserialize()?;

    let certificate = wrapper.certificate.as_ref();
    let common_name = certificate.get_common_name()?;
    let user_id = match certificate.get_user_id()? {
        Some(inner) => inner,
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err("User_id missing from certificate")).await
    };

    let filtre = doc! { "uuid_appareil": &common_name, "user_id": &user_id };
    let ops = doc! {
        "$set": { "fingerprint": &commande.fingerprint },
        "$setOnInsert": {
            "uuid_appareil": common_name,
            "user_id": user_id,
            CHAMP_CREATION: Utc::now()
        },
        "$currentDate": { CHAMP_MODIFICATION: true }
    };

    let collection = mongo.get_collection(COLLECTIONS_RELAIS)?;
    collection
        .update_one(filtre, ops)
        .upsert(true)
        .await?;

    outbound.respond(wrapper.delivery_info, ErrorMessage::ok()).await
}

pub async fn update_device_command<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    transaction: &SenseursPassifsTransactionService,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    let user_id = match wrapper.get_certificate_user_id() {
        Some(user_id) => user_id,
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err("User_id missing from certificate")).await
    };
    // Deserialize, this validates the structure
    let transaction_value: TransactionMajAppareil = wrapper.message.deserialize()?;

    let device_collection = mongo.get_collection_typed::<DocAppareil>(COLLECTIONS_APPAREILS)?;
    let filtre = doc! { CHAMP_UUID_APPAREIL: &transaction_value.uuid_appareil, CHAMP_USER_ID: &user_id };
    if device_collection.find_one(filtre.clone()).await?.is_none() {
        return outbound.respond(wrapper.delivery_info, ErrorMessage::err("Unknown device")).await
    }

    // Run transaction updates
    let delivery_info = wrapper.delivery_info.clone();
    transaction.process_transaction(wrapper.into(), None).await?;

    // Reload updated device
    let device = match device_collection.find_one(filtre.clone()).await? {
        Some(device) => device,
        None => return outbound.respond(delivery_info, ErrorMessage::err("Unknown device after transaction ran")).await
    };

    // Emit events

    // Web update event
    let routing = RoutageMessageAction::builder(
        DOMAINE_NOM,
        TRANSACTION_MAJ_APPAREIL,
        vec![Securite::L2Prive]
    )
        .partition(&user_id)
        .build();
    outbound.emit_event(routing, &device).await?;

    if let Some(configuration) = &device.configuration {
        // Update configuration
        let routing = RoutageMessageAction::builder(
            DOMAINE_NOM,
            EVENEMENT_MAJ_CONFIGURATION_APPAREIL,
            vec![Securite::L2Prive]
        )
            .partition(&user_id)
            .build();
        let configuration_event = json!({
            CHAMP_USER_ID: &user_id,
            CHAMP_UUID_APPAREIL: &transaction_value.uuid_appareil,
            CHAMP_TIMEZONE: configuration.timezone.as_ref(),
        });
        outbound.emit_event(routing, &configuration_event).await?;

        // Update displays
        if let Some(displays) = &configuration.displays {
            let routing = RoutageMessageAction::builder(
                DOMAINE_NOM,
                EVENEMENT_MAJ_DISPLAYS,
                vec![Securite::L2Prive]
            )
                .partition(&user_id)
                .build();
            let displays_event = json!({
                CHAMP_UUID_APPAREIL: &transaction_value.uuid_appareil,
                "displays": displays
            });
            outbound.emit_event(routing, &displays_event).await?;
        }

        // Update programs
        if let Some(programmes) = &configuration.programmes {
            let routing = RoutageMessageAction::builder(
                DOMAINE_NOM,
                EVENEMENT_MAJ_PROGRAMMES,
                vec![Securite::L2Prive]
            )
                .partition(&user_id)
                .build();
            let programs_event = json!({
                CHAMP_UUID_APPAREIL: &transaction_value.uuid_appareil,
                "programmes": programmes
            });
            outbound.emit_event(routing, &programs_event).await?;
        }
    }

    // Respond with complete updated device document
    outbound.respond(delivery_info, device).await
}

async fn show_hide_sensor_command<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    transaction: &SenseursPassifsTransactionService,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    // Validate the content of the transaction
    let command: TransactionShowHideSensor = wrapper.message.deserialize()?;
    let user_id = match wrapper.get_certificate_user_id() {
        Some(user_id) => user_id,
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err("Certificate does not have a user id")).await
    };

    let collection = mongo.get_collection_typed::<DocAppareil>(COLLECTIONS_APPAREILS)?;
    let filtre = doc! { CHAMP_USER_ID: &user_id, CHAMP_UUID_APPAREIL: &command.uuid_appareil };
    if let Some(device_doc) = collection.find_one(filtre).await? {
        let delivery_info = wrapper.delivery_info.clone();

        // Process the transaction database updates
        transaction.process_transaction(wrapper.into(), None).await?;

        let routage_evenement = RoutageMessageAction::builder(
            DOMAINE_NOM,
            TRANSACTION_MAJ_APPAREIL,
            vec![Securite::L2Prive]
        )
            .partition(&user_id)
            .build();
        outbound.emit_event(routage_evenement, &device_doc).await?;
        outbound.respond(delivery_info, ErrorMessage::ok()).await
    } else {
        outbound.respond(wrapper.delivery_info, ErrorMessage::err("Unknown device")).await
    }
}

#[derive(Debug, Clone, Serialize)]
struct RegisterDeviceCertificateResponse {
    ok: bool,
    certificat: Vec<String>,
}

async fn register_device_command<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    let command: CommandeInscrireAppareil = wrapper.message.deserialize()?;
    debug!("Registering device {}", command.uuid_appareil);

    let collection = mongo.get_collection_typed::<DocAppareil>(COLLECTIONS_APPAREILS)?;
    let filtre = doc! { CHAMP_USER_ID: &command.user_id, CHAMP_UUID_APPAREIL: &command.uuid_appareil };
    let device_doc = match collection.find_one(filtre.clone()).await? {
        Some(device_doc) => device_doc,
        None => create_device_during_registration(mongo, &command).await?
    };

    match device_doc.certificat {
        Some(certificate) => {
            let response = RegisterDeviceCertificateResponse { ok: true, certificat: certificate };
            // Use the public key to ensure the certificates match
            if Some(&command.cle_publique) == device_doc.cle_publique.as_ref() {
                debug!("Matching fingerprint for certificate (Public Key), sending certificate");
                outbound.respond(wrapper.delivery_info, response).await
            } else {
                // We have a mismatch between the CSR and the existing certificate
                debug!("We received and updated CSR from device, throw away existing cert/csr");
                update_device_csr(mongo, &command).await?;
                outbound.respond(wrapper.delivery_info, ErrorMessage::ok()).await
            }
        },
        None => {
            debug!("No certificate in the database, keep the incoming CSR for signing by user");
            update_device_csr(mongo, &command).await?;

            // Respond OK to device
            outbound.respond(wrapper.delivery_info, ErrorMessage::ok()).await
        }
    }
}

async fn update_device_csr(mongo: &dyn MongoDao, command: &CommandeInscrireAppareil) -> Result<(), CommonError> {
    let collection = mongo.get_collection(COLLECTIONS_APPAREILS)?;
    let filtre = doc! { CHAMP_USER_ID: &command.user_id, CHAMP_UUID_APPAREIL: &command.uuid_appareil };
    let ops = doc! {
        "$set": {
            "cle_publique": &command.cle_publique,
            "csr": &command.csr,
        },
        "$unset": {"certificat": true, "fingerprint": true},
        "$currentDate": {CHAMP_MODIFICATION: true},
    };
    collection.update_one(filtre.clone(), ops).await?;
    Ok(())
}

async fn create_device_during_registration<M>(
    mongo: &M,
    command: &CommandeInscrireAppareil,
) -> Result<DocAppareil, CommonError> where M: MongoDaoTyped {
    let doc_appareil = DocAppareil {
        uuid_appareil: command.uuid_appareil.clone(),
        instance_id: Some(command.instance_id.clone()),
        user_id: Some(command.user_id.clone()),
        cle_publique: None,
        csr: None,
        certificat: None,
        fingerprint: None,
        senseurs: None,
        derniere_lecture: None,
        configuration: None,
        displays: None,
        programmes: None,
        persiste: None,
        types_donnees: None,
        supprime: None,
        connecte: None,
        version: None,
    };

    let mut set_on_insert = bson::serialize_to_document(&doc_appareil)?;
    set_on_insert.insert(CHAMP_CREATION, Utc::now());

    let ops = doc! {
        "$setOnInsert": set_on_insert,
        "$set": {
            CHAMP_MODIFICATION: Utc::now(),
        }
    };

    let filtre = doc! { CHAMP_USER_ID: &command.user_id, CHAMP_UUID_APPAREIL: &command.uuid_appareil };
    let collection = mongo.get_collection_typed::<DocAppareil>(COLLECTIONS_APPAREILS)?;
    let _result = collection.update_one(filtre, ops).upsert(true).await?;

    // Return the new document
    Ok(doc_appareil)
}

#[derive(Clone, Debug, Serialize)]
struct DeviceChallengeCommandResponse {
    ok: bool,
    uuid_appareil: String,
    challenge: Vec<u8>,
    cle_publique: String,
    fingerprint: String,
}

async fn device_challenge_command<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped
{
    let command: CommandeChallengeAppareil = wrapper.message.deserialize()?;
    debug!("Challenge for device {}", command.uuid_appareil);

    let user_id = match wrapper.get_certificate_user_id() {
        Some(user_id) => user_id,
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err("Certificate does not have a user id")).await
    };

    let collection = mongo.get_collection_typed::<DocAppareil>(COLLECTIONS_APPAREILS)?;
    let filtre = doc! { CHAMP_USER_ID: &user_id, CHAMP_UUID_APPAREIL: &command.uuid_appareil };
    let device_doc = match collection.find_one(filtre).await? {
        Some(doc) => doc,
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err("Device not found")).await
    };

    // Extract fields required for challenge
    let (instance_id, cle_publique, fingerprint) = match (
        device_doc.instance_id.as_ref(),
        device_doc.cle_publique.as_ref(),
        device_doc.fingerprint.as_ref()
    ) {
        (
            Some(instance_id),
            Some(cle_publique),
            Some(fingerprint)
        ) => (
            instance_id.clone(),
            cle_publique.clone(),
            fingerprint.clone()
        ),
        _ => {
            debug!("Device doc missing some fields (instance_id, cle_publique, fingerprint): {:?}", device_doc);
            return outbound.respond(wrapper.delivery_info, ErrorMessage::err("Public key/fingerprint not initialized")).await
        }
    };

    let routing = RoutageMessageAction::builder(
        ROLE_RELAI_NOM,
        COMMANDE_CHALLENGE_APPAREIL,
        vec![Securite::L2Prive]
    )
        .blocking(false)
        .partition(instance_id)
        .build();

    // TODO - fix challenge mapping (Vec<u8>?)
    let challenge_command = DeviceChallengeCommandResponse {
        ok: true,
        uuid_appareil: command.uuid_appareil,
        challenge: command.challenge,
        cle_publique,
        fingerprint,
    };
    outbound.send_command(routing, challenge_command).await?;

    outbound.respond(wrapper.delivery_info, ErrorMessage::ok()).await
}

async fn sign_device_command<M>(
    pki: &dyn PkiService,
    mongo: &M,
    outbound: &MessageOutboundFacade,
    transaction: &SenseursPassifsTransactionService,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped
{
    let command: CommandeSignerAppareil = wrapper.message.deserialize()?;
    debug!("Sign device {}", command.uuid_appareil);

    let user_id = match wrapper.get_certificate_user_id() {
        Some(user_id) => user_id,
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err("Certificate does not have a user id")).await
    };

    // Determine if this is an auto-renewal
    let mut renewal = false;
    if command.csr.is_some() {
        let common_name = wrapper.certificate.get_common_name()?;
        if command.uuid_appareil.as_str() == common_name.as_str() {
            debug!("Valid renewal request for device {}", common_name);
            renewal = true;
        }
    }

    let collection = mongo.get_collection_typed::<DocAppareil>(COLLECTIONS_APPAREILS)?;
    let filtre_appareil = doc! {"uuid_appareil": &command.uuid_appareil, "user_id": &user_id,};
    let device_doc = match collection.find_one(filtre_appareil).await? {
        Some(doc) => doc,
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err("Renewal denied, unknown device")).await
    };

    let certificate = match renewal {
        true => {
            sign_certificate(
                mongo,
                outbound,
                pki,
                user_id.as_str(),
                &device_doc,
                command.csr.as_ref(),
            ).await?
        }
        false => match device_doc.certificat {
            Some(c) => c,
            None => {
                sign_certificate(
                    mongo,
                    outbound,
                    pki,
                    user_id.as_str(),
                    &device_doc,
                    command.csr.as_ref(),
                ).await?
            }
        }
    };

    if ! renewal && wrapper.certificate.verifier_roles_string(vec!["navigateur".to_string()])? {
        if device_doc.persiste != Some(true) {
            debug!("This is a user signing the certificate of a new device, create init transaction for rebuild");
            let transaction_init = TransactionInitialiserAppareil {
                uuid_appareil: device_doc.uuid_appareil.to_owned(),
                user_id,
            };
            transaction.process_value(
                DOMAINE_NOM,
                TRANSACTION_INIT_APPAREIL,
                serde_json::to_value(transaction_init)?,
                None
            ).await?;
        }
    }

    let certificate_response = RegisterDeviceCertificateResponse { ok: true, certificat: certificate };
    outbound.respond(wrapper.delivery_info, certificate_response).await
}

async fn sign_certificate<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    pki: &dyn PkiService,
    user_id: &str,
    doc_appareil: &DocAppareil,
    csr_inclus: Option<&String>,
) -> Result<Vec<String>, CommonError> where M: MongoDaoTyped {
    let csr = match csr_inclus {
        Some(c) => c.to_owned(),
        None => match doc_appareil.csr.as_ref() {
            Some(c) => c.to_owned(),
            None => return Err(CommonError::Str("CSR missing from command"))
        }
    };

    debug!("signer_certificat Aucun certificat, faire demande de signature");
    let routage = RoutageMessageAction::builder(
        DOMAINE_PKI,
        "signerCsr",
        vec![Securite::L1Public]
    ).build();

    let command = json!({
        "csr": csr,  // &doc_appareil.csr,
        "roles": ["senseurspassifs"],
        "user_id": user_id,
    });
    debug!("Sending command to sign device : {:?}", command);
    let reponse: ReponseCertificat = match outbound.send_command(routage, &command).await? {
        Some(r) => r.message.deserialize()?,
        None => return Err(CommonError::Str("No response receive on sign certificate command"))
    };

    debug!("signer_certificat Reponse : {:?}", reponse);
    if let Some(true) = reponse.ok {
        let (certificat, fingerprint) = match &reponse.certificat {
            Some(c) => {
                // Validate that the new PEM is correct, get fingerprint
                let cert = pki.validate_pem(c.join("\n").as_str(), None, None)?;
                let fingerprint = cert.fingerprint()?;
                (c.to_owned(), fingerprint)
            },
            None => Err(CommonError::Str("Incorrect server response on device signing request (cert)"))?
        };

        let ops = doc! {
            "$set": {
                "certificat": &reponse.certificat,
                "fingerprint": fingerprint,
            },
            "$unset": {"csr": true},
            "$currentDate": {CHAMP_MODIFICATION: true, "certificat_signature_date": true},
        };

        let collection = mongo.get_collection(COLLECTIONS_APPAREILS)?;
        let filtre_appareil = doc! {"uuid_appareil": &doc_appareil.uuid_appareil, "user_id": &user_id,};
        collection.update_one(filtre_appareil, ops).await?;

        Ok(certificat)  // Retourner certificat via reponse
    } else {
        Err(CommonError::Str("Incorrect server response on device signing request (ok=false)"))?
    }
}

async fn disconnect_relay_command<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped
{
    if !(wrapper.certificate.verifier_roles_string(vec!["senseurspassifs_relai".to_string()])?) {
        return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(401, "Access refused")).await
    }
    if !(wrapper.certificate.verifier_exchanges(vec![Securite::L2Prive])?) {
        return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(401, "Access refused")).await
    }

    let instance_id = wrapper.certificate.get_common_name()?;

    let collection = mongo.get_collection_typed::<DocAppareil>(COLLECTIONS_APPAREILS)?;

    // Emit a present event (disconnected) for all devices on the relay
    let filtre = doc!{ "instance_id": &instance_id, "connecte": true };
    let mut cursor = collection.find(filtre).await?;
    while let Some(device_doc) = cursor.next().await {
        let device_doc = device_doc?;
        if let Some(user_id) = device_doc.user_id {
            let evenement_reemis = EvenementPresenceAppareilUser {
                uuid_appareil: device_doc.uuid_appareil,
                user_id,
                version: device_doc.version,
                connecte: false
            };
            let routage = RoutageMessageAction::builder(
                DOMAINE_NOM,
                "presenceAppareil",
                vec![Securite::L2Prive]
            )
                .partition(&evenement_reemis.user_id)
                .build();
            outbound.emit_event(routage, &evenement_reemis).await?;
        }
    }

    // Reset connection status on all devices for the relay
    let ops = doc! {
        "$unset": {"instance_id": true},
        "$set": {"connecte": false},
        "$currentDate": {CHAMP_MODIFICATION: true},
    };
    let filtre = doc!{ "instance_id": instance_id, "connecte": true };
    collection.update_many(filtre, ops).await?;

    outbound.respond(wrapper.delivery_info, ErrorMessage::ok()).await
}

async fn trigger_complete_backup(
    outbound: &MessageOutboundFacade,
    backup: &dyn BackupService,
    wrapper: MessageValidated
) -> Result<(), CommonError> {
    // Verify authorization
    let admin = wrapper.certificate.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)?;
    if ! admin {
        let response = ErrorMessage { ok: false, code: Some(401), err: Some("Must be admin to trigger".to_string()) };
        outbound.respond(wrapper.delivery_info, response).await.ok();
        return Err(CommonError::Str("Access denied, must be admin"))
    } else {
        let admin_username = wrapper.certificate.get_common_name().unwrap_or("NA".to_string());
        let admin_user_id = wrapper.certificate.get_user_id()?.unwrap_or("NA".to_string());
        info!("Backup triggered by command from {} (user_id {})", admin_username, admin_user_id);
    }

    match backup.backup_domain(DOMAINE_NOM, COLLECTION_NAME_REDOLOG, false).await {
        Ok(result) => {
            let version = match result {
                Some(result) => {
                    debug!("Backup done, version: {:?}", result.version);
                    result.version
                }
                None => {
                    debug!("Backup done, no results");
                    None
                }
            };
            outbound.respond(wrapper.delivery_info, ErrorMessage::ok()).await.ok();

            // Try to sync files
            match backup.transfer_backup_files_to_filehost(DOMAINE_NOM).await {
                Ok(()) => {
                    // Emit the backup done event. This tells the filecontroler to sync backup files
                    // across all filehosts.
                    debug!("File transfer ok, indicating backup {:?} done via broadcast", version);
                    outbound.emit_backup_event(BackupEvent::new_done(DOMAINE_NOM, version)).await.ok();
                },
                Err(e) => error!("Error uploading backup files to filehost after manual backup: {}", e)
            }

            Ok(())
        },
        Err(e) => {
            let response = ErrorMessage { ok: false, code: Some(500), err: Some(e.to_string()) };
            outbound.respond(wrapper.delivery_info, response).await.ok();
            Err(e)
        }
    }
}
