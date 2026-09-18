// mod requetes;
mod common;
// mod lectures;
// mod transactions;
// mod commandes;
// mod evenements;
// mod builder;
// mod domain_manager;
mod constants;
// mod maintenance;
pub mod external;
pub mod flow;
pub mod state;
pub mod models;

use crate::common::DOMAINE_NOM;
use crate::state::AppContext;
use millegrilles_common_rust::tracing::{info, warn};
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;
use millegrilles_common_rust::v3::PresenceService;
use millegrilles_common_rust::{rustls, tokio as tokio};
use millegrilles_common_rust::{tracing_subscriber, tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt}};

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    init_resources();

    info!("Starting SenseursPassifs backend service");

    // Start the application by creating the context. This starts all threads and connections.
    let mut context = AppContext::new().await.expect("AppContext::new");
    let shutdown_token = context.shutdown_token.clone();

    let shutdown_signal = async {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigint = signal(SignalKind::interrupt()).expect("failed to install sigint handler");
        let mut sigterm = signal(SignalKind::terminate()).expect("failed to install sigterm handler");

        tokio::select! {
            _ = sigint.recv() => info!("Received SIGINT (Ctrl+C)"),
            _ = sigterm.recv() => info!("Received SIGTERM (Docker/K8s)"),
        }
    };

    init_tasks(context.outbound.as_ref()).await;

    tokio::select! {
        _ = shutdown_signal => {
            info!("Shutdown signal received. Triggering cancellation...");
            shutdown_token.cancel();
        }
    }

    info!("Waiting for workers to finish (15s limit)...");
    match tokio::time::timeout(std::time::Duration::from_secs(15), async {
        while context.join_set.join_next().await.is_some() {}
    }).await {
        Ok(_) => info!("Shutdown complete."),
        Err(_) => warn!("Grace period expired! Forcing exit."),
    }
}

fn init_resources() {
    let rust_log_var = std::env::var("RUST_LOG").unwrap_or("error,millegrilles_maitredescles=warn,millegrilles_common_rust=warn".to_string());
    // env_logger::init();
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(rust_log_var))
        .with(tracing_subscriber::fmt::layer())
        .init();

    rustls::crypto::ring::default_provider().install_default()
        .expect("Failed to install rustls crypto provider");
}

/// This runs once on startup after all the wiring is done and threads are started
async fn init_tasks(outbound: &MessageOutboundFacade) {
    // Wait for queues to emit initial domain presence
    match outbound.wait_ready(Some(5_000)).await {
        Ok(()) => {
            if let Err(e) = outbound.emit_domain_presence(DOMAINE_NOM, None).await {
                warn!("Error emitting initial domain presence: {}", e);
            }
        },
        Err(e) => {
            warn!("Error waiting for queues to be ready, not emitting inital domain presence: {:?}", e);
        }
    }
}

#[cfg(test)]
pub mod test_setup {
    use millegrilles_common_rust::tracing::debug;

    pub fn setup(nom: &str) {
        //let _ = env_logger::builder().is_test(true).try_init();
        debug!("Running {}", nom);
    }
}
