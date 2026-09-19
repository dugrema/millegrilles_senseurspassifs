use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::configuration::ConfigMessages;
use millegrilles_common_rust::constantes::{FIELD_BID, FIELD_DATE_PROCESSED, FIELD_PROCESSED, INDEX_BID, INDEX_DATE_PROCESSED, TRANSACTION_CHAMP_ID};
use millegrilles_common_rust::mongo_dao::{ChampIndex, IndexOptions, MongoDao};
use crate::common::{CHAMP_DERNIERE_LECTURE, CHAMP_HEURE, CHAMP_PRESENT, CHAMP_SENSEUR_ID, CHAMP_USER_ID, CHAMP_UUID_APPAREIL, COLLECTIONS_APPAREILS, COLLECTIONS_LECTURES, COLLECTIONS_NOTIFICATIONS_USAGERS, COLLECTIONS_RELAIS, COLLECTIONS_SENSEURS_HORAIRE, INDEX_APPAREILS_DERNIERE_LECTURE, INDEX_LECTURES_HORAIRE, INDEX_LECTURES_HORAIRE_RAPPORT, INDEX_LECTURES_SENSEURS, INDEX_USER_APPAREILS, INDEX_USER_APPAREIL_RELAIS, INDEX_USER_NOTIFICATIONS};

pub const COLLECTION_NAME_REDOLOG: &str = "SenseursPassifs/redolog";
pub const COLLECTION_NAME_TRACKING: &str = "SenseursPassifs/tracking";

pub const INDEX_REDO_LOG_ID: &str = "redo_log_id";

pub async fn create_index_mongodb(db: &dyn MongoDao, config: &dyn ConfigMessages) -> Result<(), CommonError> {
    db.create_index(
        config,
        COLLECTION_NAME_REDOLOG,
        vec!(
            ChampIndex { nom_champ: String::from(TRANSACTION_CHAMP_ID), direction: 1 },
        ),
        Some(IndexOptions {
            nom_index: Some(String::from(INDEX_REDO_LOG_ID)),
            unique: true,
        }),
    ).await?;

    db.create_index(
        config,
        COLLECTION_NAME_REDOLOG,
        vec!(
            ChampIndex { nom_champ: String::from(FIELD_PROCESSED), direction: 1 },
        ),
        Some(IndexOptions {
            nom_index: Some(String::from(INDEX_DATE_PROCESSED)),
            unique: false,
        }),
    ).await?;

    db.create_index(
        config,
        COLLECTION_NAME_TRACKING,
        vec!(
            ChampIndex { nom_champ: String::from(FIELD_BID), direction: 1 },
        ),
        Some(IndexOptions {
            nom_index: Some(String::from(INDEX_BID)),
            unique: true,
        }),
    ).await?;

    db.create_index(
        config,
        COLLECTION_NAME_TRACKING,
        vec!(
            ChampIndex { nom_champ: String::from(FIELD_DATE_PROCESSED), direction: 1 },
        ),
        Some(IndexOptions {
            nom_index: Some(String::from(INDEX_DATE_PROCESSED)),
            unique: false,
        })
    ).await?;

    db.create_index(
        config,
        COLLECTIONS_APPAREILS,
        vec!(
            ChampIndex {nom_champ: String::from(CHAMP_USER_ID), direction: 1},
            ChampIndex {nom_champ: String::from(CHAMP_UUID_APPAREIL), direction: 1},
        ),
        Some(IndexOptions {
            nom_index: Some(String::from(INDEX_USER_APPAREILS)),
            unique: true,
        })
    ).await?;

    db.create_index(
        config,
        COLLECTIONS_LECTURES,
        vec!(
            ChampIndex {nom_champ: String::from(CHAMP_USER_ID), direction: 1},
            ChampIndex {nom_champ: String::from(CHAMP_UUID_APPAREIL), direction: 1},
            ChampIndex {nom_champ: String::from(CHAMP_SENSEUR_ID), direction: 1},
            ChampIndex {nom_champ: String::from(CHAMP_HEURE), direction: 1},
        ),
        Some(IndexOptions {
            nom_index: Some(String::from(INDEX_LECTURES_SENSEURS)),
            unique: true,
        })
    ).await?;

    db.create_index(
        config,
        COLLECTIONS_APPAREILS,
        vec!(
            ChampIndex {nom_champ: String::from(CHAMP_DERNIERE_LECTURE), direction: 1},
            ChampIndex {nom_champ: String::from(CHAMP_PRESENT), direction: 1},
        ),
        Some(IndexOptions {
            nom_index: Some(String::from(INDEX_APPAREILS_DERNIERE_LECTURE)),
            unique: false,
        })
    ).await?;

    db.create_index(
        config,
        COLLECTIONS_SENSEURS_HORAIRE,
        vec!(
            ChampIndex {nom_champ: String::from(CHAMP_USER_ID), direction: 1},
            ChampIndex {nom_champ: String::from(CHAMP_UUID_APPAREIL), direction: 1},
            ChampIndex {nom_champ: String::from(CHAMP_SENSEUR_ID), direction: 1},
            ChampIndex {nom_champ: String::from(CHAMP_HEURE), direction: 1},
        ),
        Some(IndexOptions {
            nom_index: Some(String::from(INDEX_LECTURES_HORAIRE)),
            unique: true,
        })
    ).await?;

    db.create_index(
        config,
        COLLECTIONS_LECTURES,
        vec!(
            ChampIndex {nom_champ: String::from(CHAMP_HEURE), direction: 1},
        ),
        Some(IndexOptions {
            nom_index: Some(String::from(INDEX_LECTURES_HORAIRE_RAPPORT)),
            unique: false,
        })
    ).await?;

    db.create_index(
        config,
        COLLECTIONS_NOTIFICATIONS_USAGERS,
        vec!(
            ChampIndex {nom_champ: String::from(CHAMP_USER_ID), direction: 1},
        ),
        Some(IndexOptions {
            nom_index: Some(String::from(INDEX_USER_NOTIFICATIONS)),
            unique: true,
        })
    ).await?;

    db.create_index(
        config,
        COLLECTIONS_RELAIS,
        vec!(
            ChampIndex {nom_champ: String::from(CHAMP_UUID_APPAREIL), direction: 1},
            ChampIndex {nom_champ: String::from(CHAMP_USER_ID), direction: 1},
        ),
        Some(IndexOptions {
            nom_index: Some(String::from(INDEX_USER_APPAREIL_RELAIS)),
            unique: true,
        })
    ).await?;

    Ok(())
}
