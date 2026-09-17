use std::sync::Arc;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::serde_json::Value;
use millegrilles_common_rust::v3::{ConfigService, FormatService, TransactionRouter, TransactionService};
use millegrilles_common_rust::v3::impls::transaction_service::TransactionServiceImpl;
use millegrilles_common_rust::v3::models::{TransactionOperationAggregator, TransactionWrapper};
use crate::external::mongo::COLLECTION_NAME_REDOLOG;

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
            COLLECTION_NAME_REDOLOG.to_string(),
            Box::new(router),
        );

        Self { transactions: Box::new(service) }
    }

    pub async fn process_value(&self, domain: &str, action: &str, value: Value) -> Result<(), CommonError> {
        self.transactions.process_value(domain, action, value).await
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
        _wrapper: TransactionWrapper
    ) -> Result<TransactionOperationAggregator, CommonError> {
        match action.as_str() {
            // TRANSACTION_CLE => legacy_transaction_cle(self.mongo.as_ref(), wrapper).await,
            // TRANSACTION_CLE_V2 => save_new_key(self.mongo.as_ref(), wrapper, self.ignore_duplicates).await,
            _ => Err(CommonError::Str("Unknown transaction action"))
        }
    }
}
