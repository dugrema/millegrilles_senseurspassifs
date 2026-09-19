use crate::common::*;
use crate::external::mongo::{COLLECTION_NAME_REDOLOG, COLLECTION_NAME_TRACKING};
use crate::models::{SenseurHoraireRow, TransactionLectureHoraire, TransactionMajAppareil, TransactionShowHideSensor};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::bson;
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::chrono::Utc;
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::mongodb::ClientSession;
use millegrilles_common_rust::mongodb::options::{UpdateOneModel, WriteModel};
use millegrilles_common_rust::serde_json::Value;
use millegrilles_common_rust::v3::impls::transaction_service::TransactionServiceImpl;
use millegrilles_common_rust::v3::models::{BatchInsertions, TransactionOperationAggregator, TransactionWrapper};
use millegrilles_common_rust::v3::{ConfigService, FormatService, TransactionRouter, TransactionService};
use std::sync::Arc;

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
            TRANSACTION_SENSEUR_HORAIRE => process_hourly_device_readings(self.mongo.as_ref(), wrapper, self.ignore_duplicates).await,
            TRANSACTION_MAJ_APPAREIL => update_device_transaction(self.mongo.as_ref(), wrapper).await,
            TRANSACTION_SHOW_HIDE_SENSOR => show_hide_sensor_transaction(self.mongo.as_ref(), wrapper).await,

            // Legacy
            TRANSACTION_LECTURE => panic!("Obsolete"),
            TRANSACTION_MAJ_SENSEUR => panic!("Obsolete"),
            TRANSACTION_MAJ_NOEUD => panic!("Obsolete"),
            TRANSACTION_SUPPRESSION_SENSEUR => panic!("Obsolete"),
            TRANSACTION_INIT_APPAREIL => panic!("Obsolete"),
            TRANSACTION_APPAREIL_SUPPRIMER => panic!("Obsolete"),
            TRANSACTION_APPAREIL_RESTAURER => panic!("Obsolete"),
            TRANSACTION_MAJ_CONFIGURATION_USAGER => panic!("Obsolete"),
            TRANSACTION_SAUVEGARDER_PROGRAMME => panic!("Obsolete"),
            _ => Err(CommonError::Str("Unknown transaction action"))
        }
    }
}

async fn process_hourly_device_readings(
    mongo: &dyn MongoDao,
    wrapper: TransactionWrapper,
    ignore_duplicates: bool,
) -> Result<TransactionOperationAggregator, CommonError> {
    let mut aggregator = TransactionOperationAggregator::new();
    let transaction_value: TransactionLectureHoraire = wrapper.message.deserialize()?;
    let senseur_horaire_row = SenseurHoraireRow::from(&transaction_value);

    if ignore_duplicates {
        // Restoring from backup
        let filtre = doc!{
            CHAMP_USER_ID: &senseur_horaire_row.user_id,
            CHAMP_UUID_APPAREIL: &senseur_horaire_row.uuid_appareil,
            "senseur_id": &senseur_horaire_row.senseur_id,
            "heure": &senseur_horaire_row.heure
        };
        let collection = mongo.get_collection(COLLECTIONS_SENSEURS_HORAIRE)?;
        let ops = doc! {
            "$setOnInsert": bson::serialize_to_document(&senseur_horaire_row)?,
        };
        let update_model = WriteModel::UpdateOne(
            UpdateOneModel::builder()
                .upsert(true)
                .namespace(collection.namespace())
                .filter(filtre)
                .update(ops)
                .build()
        );
        // Can use unordered because duplicates are identical entries (ideally would be insert)
        aggregator.unordered = Some(vec![update_model]);
    } else {
        // Normal operation, fail if duplicate entry is created
        aggregator.batch_insertion(BatchInsertions::new(
            COLLECTIONS_SENSEURS_HORAIRE,
            vec![bson::serialize_to_document(&senseur_horaire_row)?]
        ))?;
    }

    Ok(aggregator)
}

async fn update_device_transaction(
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

async fn show_hide_sensor_transaction(
    mongo: &dyn MongoDao,
    wrapper: TransactionWrapper,
) -> Result<TransactionOperationAggregator, CommonError> {
    let user_id = match wrapper.get_certificate_user_id() {
        Some(user_id) => user_id,
        None => return Err(CommonError::Str("Missing user_id from certificate"))
    };

    // Deserialize, this validates the structure
    let transaction_value: TransactionShowHideSensor = wrapper.message.deserialize()?;

    let mut aggregator = TransactionOperationAggregator::new();

    let collection = mongo.get_collection(COLLECTIONS_APPAREILS)?;
    let deleted_flag = match transaction_value.hide {
        Some(true) => true,
        _ => false
    };

    let mut ops = doc! {
        "$currentDate": { CHAMP_MODIFICATION: true }
    };
    if deleted_flag {
        ops.insert("$addToSet", doc!{"configuration.cacher_senseurs": transaction_value.senseur_id});
    } else {
        ops.insert("$pull", doc!{"configuration.cacher_senseurs": transaction_value.senseur_id});
    }

    let filtre = doc! { CHAMP_USER_ID: &user_id, CHAMP_UUID_APPAREIL: &transaction_value.uuid_appareil };
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
