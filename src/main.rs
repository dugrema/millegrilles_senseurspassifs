mod requetes;
mod common;
mod lectures;
mod transactions;
mod commandes;
mod evenements;
mod builder;
mod domain_manager;
mod constants;
mod maintenance;

use log::{info};
use millegrilles_common_rust::{rustls, tokio as tokio};
// use crate::domaines_senseurspassifs::run;
use crate::builder::run;

fn main() {
    init_resources();

    info!("Demarrer le contexte");
    executer()
}

fn init_resources() {
    let rust_log_var = std::env::var("RUST_LOG").unwrap_or("error,millegrilles_maitredescles=warn,millegrilles_common_rust=warn".to_string());
    env_logger::init();
    // tracing_subscriber::registry()
    //     .with(tracing_subscriber::EnvFilter::new(rust_log_var))
    //     .with(tracing_subscriber::fmt::layer())
    //     .init();

    rustls::crypto::ring::default_provider().install_default()
        .expect("Failed to install rustls crypto provider");
}

#[tokio::main(flavor = "current_thread")]
// #[tokio::main(flavor = "multi_thread", worker_threads = 5)]
async fn executer() {
    run().await
}

#[cfg(test)]
pub mod test_setup {
    use log::{debug};

    pub fn setup(nom: &str) {
        let _ = env_logger::builder().is_test(true).try_init();
        debug!("Running {}", nom);
    }
}
