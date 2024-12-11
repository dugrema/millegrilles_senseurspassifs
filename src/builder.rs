use crate::domain_manager::SenseursPassifsDomainManager;
use log::{debug, info, warn};
use millegrilles_common_rust::{chrono, tokio};
use millegrilles_common_rust::chrono::Utc;
use millegrilles_common_rust::configuration::{ConfigMessages, IsConfigNoeud};
use millegrilles_common_rust::domaines_v2::GestionnaireDomaineSimple;
use millegrilles_common_rust::futures::stream::FuturesUnordered;
use millegrilles_common_rust::middleware_db_v2::preparer as preparer_middleware;
use millegrilles_common_rust::mongo_dao::{ChampIndex, IndexOptions, MongoDao};
use millegrilles_common_rust::static_cell::StaticCell;
use millegrilles_common_rust::tokio::task::JoinHandle;
use millegrilles_common_rust::tokio::spawn;
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::middleware::{charger_certificats_chiffrage, Middleware};

use crate::common::*;

static DOMAIN_MANAGER: StaticCell<SenseursPassifsDomainManager> = StaticCell::new();

pub async fn run() {

    let (middleware, futures_middleware) = preparer_middleware()
        .expect("preparer middleware");

    let (gestionnaire, futures_domaine) = initialiser(middleware).await
        .expect("initialiser domaine");

    // Test redis connection
    if let Some(redis) = middleware.redis.as_ref() {
        match redis.liste_certificats_fingerprints().await {
            Ok(fingerprints_redis) => {
                debug!("redis.liste_certificats_fingerprints Result : {:?}", fingerprints_redis);
            },
            Err(e) => warn!("redis.liste_certificats_fingerprints Error testing redis connection : {:?}", e)
        }
    }

    // Combiner les JoinHandles recus
    let mut futures = FuturesUnordered::new();
    futures.extend(futures_middleware);
    futures.extend(futures_domaine);

    // Demarrer thread d'entretien.
    futures.push(spawn(thread_entretien(gestionnaire, middleware)));

    // Le "await" maintien l'application ouverte. Des qu'une task termine, l'application arrete.
    futures.next().await;

    for f in &futures {
        f.abort()
    }

    info!("domaine_messages Attendre {} tasks restantes", futures.len());
    while futures.len() > 0 {
        futures.next().await;
    }

    info!("domaine_messages Fin execution");
}

/// Initialise le gestionnaire. Retourne les spawned tasks dans une liste de futures
/// (peut servir a canceller).
async fn initialiser<M>(middleware: &'static M) -> Result<(&'static SenseursPassifsDomainManager, FuturesUnordered<JoinHandle<()>>), CommonError>
where M: Middleware + IsConfigNoeud
{
    let config = middleware.get_configuration_noeud();
    let instance_id = config.instance_id.as_ref().expect("instance_id").to_string();

    let gestionnaire = SenseursPassifsDomainManager::new(instance_id);
    let gestionnaire = DOMAIN_MANAGER.try_init(gestionnaire)
        .expect("gestionnaire init");

    // Preparer la collection avec index
    let futures = gestionnaire.initialiser(middleware).await
        .expect("initialiser");

    // Preparer des ressources additionnelles
    // preparer_index_mongodb(middleware, gestionnaire).await
    //     .expect("preparer_index_mongodb");

    Ok((gestionnaire, futures))
}

pub async fn preparer_index_mongodb<M>(middleware: &M) -> Result<(), CommonError>
where M: MongoDao + ConfigMessages
{
    let options_appareils = IndexOptions {
        nom_index: Some(String::from(INDEX_USER_APPAREILS)),
        unique: true
    };
    let champs_index_appareils = vec!(
        ChampIndex {nom_champ: String::from(CHAMP_USER_ID), direction: 1},
        ChampIndex {nom_champ: String::from(CHAMP_UUID_APPAREIL), direction: 1},
    );
    middleware.create_index(
        middleware,
        COLLECTIONS_APPAREILS,
        champs_index_appareils,
        Some(options_appareils)
    ).await?;

    let options_lectures_senseurs = IndexOptions {
        nom_index: Some(String::from(INDEX_LECTURES_SENSEURS)),
        unique: true
    };
    let champs_index_lectures_senseurs = vec!(
        ChampIndex {nom_champ: String::from(CHAMP_USER_ID), direction: 1},
        ChampIndex {nom_champ: String::from(CHAMP_UUID_APPAREIL), direction: 1},
        ChampIndex {nom_champ: String::from("senseur_id"), direction: 1},
        ChampIndex {nom_champ: String::from("heure"), direction: 1},
    );
    middleware.create_index(
        middleware,
        COLLECTIONS_LECTURES,
        champs_index_lectures_senseurs,
        Some(options_lectures_senseurs)
    ).await?;

    // Appareils date_lecture/present
    let options_appareils_derniere_lecture = IndexOptions {
        nom_index: Some(String::from(INDEX_APPAREILS_DERNIERE_LECTURE)),
        unique: false
    };
    let champs_appareils_deniere_lecture = vec!(
        ChampIndex {nom_champ: String::from(CHAMP_DERNIERE_LECTURE), direction: 1},
        ChampIndex {nom_champ: String::from(CHAMP_PRESENT), direction: 1},
    );
    middleware.create_index(
        middleware,
        COLLECTIONS_APPAREILS,
        champs_appareils_deniere_lecture,
        Some(options_appareils_derniere_lecture)
    ).await?;

    // Lectures horaire
    let options_senseurs_horaires = IndexOptions {
        nom_index: Some(String::from(INDEX_LECTURES_HORAIRE)),
        unique: true
    };
    let champs_index_senseurs_horaire = vec!(
        ChampIndex {nom_champ: String::from(CHAMP_USER_ID), direction: 1},
        ChampIndex {nom_champ: String::from(CHAMP_UUID_APPAREIL), direction: 1},
        ChampIndex {nom_champ: String::from("senseur_id"), direction: 1},
        ChampIndex {nom_champ: String::from("heure"), direction: 1},
    );
    middleware.create_index(
        middleware,
        COLLECTIONS_SENSEURS_HORAIRE,
        champs_index_senseurs_horaire,
        Some(options_senseurs_horaires)
    ).await?;

    // Lectures horaire
    let options_senseurs_horaires_rapport = IndexOptions {
        nom_index: Some(String::from(INDEX_LECTURES_HORAIRE_RAPPORT)),
        unique: false
    };
    let champs_index_senseurs_horaire_rapport = vec!(
        ChampIndex {nom_champ: String::from("heure"), direction: 1},
    );
    middleware.create_index(
        middleware,
        COLLECTIONS_LECTURES,
        champs_index_senseurs_horaire_rapport,
        Some(options_senseurs_horaires_rapport)
    ).await?;

    // Notifications usager
    let options_notifications_usager = IndexOptions {
        nom_index: Some(String::from(INDEX_USER_NOTIFICATIONS)),
        unique: true
    };
    let champs_index_notifications_usager = vec!(
        ChampIndex {nom_champ: String::from(CHAMP_USER_ID), direction: 1},
    );
    middleware.create_index(
        middleware,
        COLLECTIONS_NOTIFICATIONS_USAGERS,
        champs_index_notifications_usager,
        Some(options_notifications_usager)
    ).await?;

    // Notifications usager
    let options_relais = IndexOptions {
        nom_index: Some(String::from(INDEX_USER_APPAREIL_RELAIS)),
        unique: true
    };
    let champs_index_relais = vec!(
        ChampIndex {nom_champ: String::from(CHAMP_UUID_APPAREIL), direction: 1},
        ChampIndex {nom_champ: String::from(CHAMP_USER_ID), direction: 1},
    );
    middleware.create_index(
        middleware,
        COLLECTIONS_RELAIS,
        champs_index_relais,
        Some(options_relais)
    ).await?;

    Ok(())
}

async fn thread_entretien<M>(_gestionnaire: &SenseursPassifsDomainManager, middleware: &M)
where M: Middleware
{
    let mut prochain_chargement_certificats_maitredescles = Utc::now();
    let intervalle_chargement_certificats_maitredescles = chrono::Duration::minutes(5);

    // Attendre 5 secondes pour init bus
    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

    loop {
        let maintenant = Utc::now();

        // Effectuer entretien
        if prochain_chargement_certificats_maitredescles < maintenant {
            match charger_certificats_chiffrage(middleware).await {
                Ok(()) => {
                    prochain_chargement_certificats_maitredescles = maintenant + intervalle_chargement_certificats_maitredescles;
                    debug!("domaines_core.entretien Prochain chargement cert maitredescles: {:?}", prochain_chargement_certificats_maitredescles);
                },
                Err(e) => warn!("domaines_core.entretien Erreur chargement certificats de maitre des cles : {:?}", e)
            }

        }

        // Sleep
        tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
    }
}
