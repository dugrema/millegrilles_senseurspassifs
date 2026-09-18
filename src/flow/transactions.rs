use std::sync::Arc;
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::bson;
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::chrono::Utc;
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::mongodb::ClientSession;
use millegrilles_common_rust::mongodb::options::{UpdateOneModel, WriteModel};
use millegrilles_common_rust::serde_json::Value;
use millegrilles_common_rust::v3::{ConfigService, FormatService, TransactionRouter, TransactionService};
use millegrilles_common_rust::v3::facades::message_inbound::MessageValidated;
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;
use millegrilles_common_rust::v3::impls::transaction_service::TransactionServiceImpl;
use millegrilles_common_rust::v3::models::{ErrorMessage, TransactionOperationAggregator, TransactionWrapper};
use crate::common::*;
use crate::external::mongo::{COLLECTION_NAME_REDOLOG, COLLECTION_NAME_TRACKING};
use crate::models::TransactionMajAppareil;

pub const TRANSACTION_LECTURE: &str = "lecture";
pub const TRANSACTION_MAJ_SENSEUR: &str = "majSenseur";
pub const TRANSACTION_MAJ_NOEUD: &str = "majNoeud";
pub const TRANSACTION_SUPPRESSION_SENSEUR: &str = "suppressionSenseur";
pub const TRANSACTION_INIT_APPAREIL: &str = "initAppareil";
pub const TRANSACTION_MAJ_APPAREIL: &str = "majAppareil";
pub const TRANSACTION_SHOW_HIDE_SENSOR: &str = "showHideSensor";
pub const TRANSACTION_SAUVEGARDER_PROGRAMME: &str = "sauvegarderProgramme";
pub const TRANSACTION_SENSEUR_HORAIRE: &str = "senseurHoraire";
pub const TRANSACTION_APPAREIL_SUPPRIMER: &str = "supprimerAppareil";
pub const TRANSACTION_APPAREIL_RESTAURER: &str = "restaurerAppareil";
pub const TRANSACTION_MAJ_CONFIGURATION_USAGER: &str = "majConfigurationUsager";

pub struct SenseursPassifsTransactionService {
    transactions: Box<dyn TransactionService>,
}

impl SenseursPassifsTransactionService {
    pub fn new(
        config: Arc<dyn ConfigService>,
        format: Arc<dyn FormatService>,
        mongo: Arc<dyn MongoDao>,
    ) -> Self {
        let router = SenseursPassifsTransactionRouter { mongo: mongo.clone(), ignore_duplicates: false };
        let service = TransactionServiceImpl::new(
            config,
            format,
            mongo,
            COLLECTION_NAME_REDOLOG.to_string(),
            COLLECTION_NAME_TRACKING.to_string(),
            Box::new(router),
        );

        Self { transactions: Box::new(service) }
    }

    pub async fn process_transaction(&self, wrapper: TransactionWrapper, session: Option<&mut ClientSession>) -> Result<(), CommonError> {
        self.transactions.process_transaction(wrapper, session).await
    }

    pub async fn process_value(&self, domain: &str, action: &str, value: Value, session: Option<&mut ClientSession>) -> Result<(), CommonError> {
        self.transactions.process_value(domain, action, value, session).await
    }
}

struct SenseursPassifsTransactionRouter {
    mongo: Arc<dyn MongoDao>,
    ignore_duplicates: bool,
}

#[async_trait]
impl TransactionRouter for SenseursPassifsTransactionRouter {
    async fn route(
        &self,
        action: String,
        wrapper: TransactionWrapper
    ) -> Result<TransactionOperationAggregator, CommonError> {
        match action.as_str() {
            TRANSACTION_SENSEUR_HORAIRE => process_hourly_device_readings(self.mongo.as_ref(), wrapper).await,
            TRANSACTION_MAJ_APPAREIL => update_device_transaction(self.mongo.as_ref(), wrapper).await,
            _ => Err(CommonError::Str("Unknown transaction action"))
        }
    }
}

async fn process_hourly_device_readings(
    mongo: &dyn MongoDao,
    wrapper: TransactionWrapper,
) -> Result<TransactionOperationAggregator, CommonError> {
    let mut aggregator = TransactionOperationAggregator::new();

    todo!();
    Ok(aggregator)

    // debug!("transaction_senseur_horaire Consommer transaction : {:?}", transaction.transaction.id);
    //     let transaction_convertie: TransactionLectureHoraire = serde_json::from_str(transaction.transaction.contenu.as_str())?;
    //     let senseur_horaire_row = SenseurHoraireRow::from(&transaction_convertie);
    //
    //     // Inserer dans la table de lectures senseurs horaires
    //     let collection = middleware.get_collection_typed::<SenseurHoraireRow>(COLLECTIONS_SENSEURS_HORAIRE)?;
    //     if middleware.get_mode_regeneration() == true {
    //         // HACK - duplicate transactions have been produced. Remove once all transactions are fixed/migrated
    //         let filtre = doc!{
    //             CHAMP_USER_ID: &transaction_convertie.user_id,
    //             CHAMP_UUID_APPAREIL: &transaction_convertie.uuid_appareil,
    //             "senseur_id": &transaction_convertie.senseur_id,
    //             "heure": &transaction_convertie.heure
    //         };
    //         // let options = FindOneOptions::builder().hint(Hint::Name("lectures_horaire".to_string())).build();
    //         if collection
    //             .find_one(filtre)
    //             .hint(Hint::Name("lectures_horaire".to_string()))
    //             .session(&mut *session)
    //             .await?.is_some()
    //         {
    //             warn!("transaction_senseur_horaire Ignoring duplicate transaction: {} on rebuild", transaction.transaction.id);
    //             return Ok(None);
    //         }
    //     }
    //
    //     collection
    //         .insert_one(&senseur_horaire_row)
    //         .session(&mut *session)
    //         .await?;
    //
    //     // Other approach - pre-commit (slow)
    //     // if middleware.get_mode_regeneration() == true {
    //     //     // Commit previous changes, the following transaction can fail on duplicates.
    //     //     session.commit_transaction().await?;
    //     //     start_transaction_regeneration(session).await?;
    //     // }
    //
    //     // if let Err(e) = collection.insert_one_with_session(&senseur_horaire_row, None, session).await {
    //     //     if middleware.get_mode_regeneration() == true {  // Rebuilding
    //     //         error!("transaction_senseur_horaire Error processing transaction, skipping: {:?}", e);
    //     //         session.abort_transaction().await?;
    //     //         start_transaction_regeneration(session).await?;
    //     //     } else {
    //     //         Err(e)?  // Re-raise error for standard transaction processing
    //     //     }
    //     // }
    //
    //     // S'assurer que l'appareil existe (e.g. pour regeneration)
    //     if middleware.get_mode_regeneration() == false {
    //         let collection = middleware.get_collection(COLLECTIONS_APPAREILS)?;
    //         let filtre = doc! {
    //             CHAMP_USER_ID: &transaction_convertie.user_id,
    //             CHAMP_UUID_APPAREIL: &transaction_convertie.uuid_appareil,
    //         };
    //         let mut ops = doc! {
    //             "$setOnInsert": {
    //                 CHAMP_USER_ID: &transaction_convertie.user_id,
    //                 CHAMP_UUID_APPAREIL: &transaction_convertie.uuid_appareil,
    //                 CHAMP_CREATION: Utc::now(),
    //                 "present": false,
    //             },
    //             "$currentDate": {
    //                 CHAMP_MODIFICATION: true,
    //             },
    //             "$addToSet": {
    //                 CHAMP_LECTURES_DISPONIBLES: &transaction_convertie.senseur_id
    //             }
    //         };
    //
    //         // Detecter type de lectures (aucun si vide)
    //         let mut type_donnees = None;
    //         for l in &transaction_convertie.lectures {
    //             type_donnees = Some(l.type_.clone());
    //             break
    //         }
    //
    //         if let Some(type_donnees) = type_donnees {
    //             ops.insert("$set", doc!{
    //                 format!("types_donnees.{}", transaction_convertie.senseur_id): type_donnees
    //             });
    //         }
    //
    //         // let options = UpdateOptions::builder().upsert(true).build();
    //         if let Err(e) = collection
    //             .update_one(filtre, ops)
    //             .upsert(true)
    //             .session(&mut *session)
    //             .await
    //         {
    //             Err(format!("transactions.transaction_initialiser_appareil Erreur chargement collection : {:?}", e))?
    //         }
    //     }
}

pub async fn update_device_transaction(
    mongo: &dyn MongoDao,
    wrapper: TransactionWrapper,
) -> Result<TransactionOperationAggregator, CommonError> {
    let user_id = match wrapper.get_certificate_user_id() {
        Some(user_id) => user_id,
        None => return Err(CommonError::Str("Missing user_id from certificate"))
    };

    // Deserialize, this validates the structure
    let transaction_value: TransactionMajAppareil = wrapper.message.deserialize()?;

    let mut aggregator = TransactionOperationAggregator::new();

    let mut set_ops = doc! {};

    if let Some(inner) = transaction_value.configuration.descriptif {
        set_ops.insert("configuration.descriptif", inner);
    }
    if let Some(inner) = transaction_value.configuration.cacher_senseurs {
        set_ops.insert("configuration.cacher_senseurs", inner);
    }
    if let Some(inner) = transaction_value.configuration.descriptif_senseurs {
        for (key, value) in inner {
            set_ops.insert(format!("configuration.descriptif_senseurs.{key}"), value);
        }
    }
    if let Some(inner) = transaction_value.configuration.displays.as_ref() {
        let bson_map = match bson::serialize_to_document(inner) {
            Ok(inner) => inner,
            Err(e) => Err(format!("senseurspassifs.transaction_maj_appareil Erreur conversion displays en bson : {:?}", e))?
        };
        set_ops.insert("configuration.displays", bson_map);
    }
    if let Some(inner) = transaction_value.configuration.programmes.as_ref() {
        let bson_map = match bson::serialize_to_document(inner) {
            Ok(inner) => inner,
            Err(e) => Err(format!("senseurspassifs.transaction_maj_appareil Erreur conversion programmes en bson : {:?}", e))?
        };
        set_ops.insert("configuration.programmes", bson_map);
    }
    if let Some(inner) = transaction_value.configuration.timezone {
        set_ops.insert("configuration.timezone".to_string(), inner);
    } else {
        // Cannot unset: several update transactions do not send this info (e.g. programs).
        // unset_ops.insert("configuration.timezone".to_string(), true);
    }
    if let Some(inner) = transaction_value.configuration.geoposition.as_ref() {
        let bson_map = match bson::serialize_to_document(inner) {
            Ok(inner) => inner,
            Err(e) => Err(format!("senseurspassifs.transaction_maj_appareil Erreur conversion geoposition en bson : {:?}", e))?
        };
        set_ops.insert("configuration.geoposition", bson_map);
    } else {
        // Cannot unset: several update transactions do not send this info (e.g. programs).
        // unset_ops.insert("configuration.geoposition", true);
    }
    if let Some(inner) = transaction_value.configuration.filtres_senseurs {
        for (key, value) in inner {
            set_ops.insert(format!("configuration.filtres_senseurs.{key}"), value);
        }
    }

    let ops = doc! {
        "$set": set_ops,
        "$setOnInsert": {
            CHAMP_CREATION: Utc::now(),
            CHAMP_UUID_APPAREIL: &transaction_value.uuid_appareil,
            CHAMP_USER_ID: &user_id,
        },
        "$currentDate": {CHAMP_MODIFICATION: true}
    };
    let filtre = doc! { CHAMP_UUID_APPAREIL: &transaction_value.uuid_appareil, CHAMP_USER_ID: &user_id };
    let collection = mongo.get_collection(COLLECTIONS_APPAREILS)?;
    let update_model = WriteModel::UpdateOne(
        UpdateOneModel::builder()
            .upsert(true)
            .namespace(collection.namespace())
            .filter(filtre)
            .update(ops)
            .build()
    );
    aggregator.ordered = Some(vec![update_model]);

    Ok(aggregator)
}
