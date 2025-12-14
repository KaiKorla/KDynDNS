use actix_web::{App, HttpServer, web};
use std::env;
use std::sync::{Arc, RwLock};
use tokio::signal::unix::{SignalKind, signal};
use tracing::{error, info};

mod auth;
mod config;
mod dns;
mod handlers;

use crate::config::AppConfig;
use crate::dns::{DnsUpdater, NsupdateDnsUpdater};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<RwLock<AppConfig>>,
    pub updater: Arc<dyn DnsUpdater>,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .without_time()
        .compact()
        .init();

    let socket_path =
        env::var("KDYNDNS_SOCKET").unwrap_or_else(|_| "/run/kdyndns.sock".to_string());
    let config_path =
        env::var("DYNDNS_CONFIG").unwrap_or_else(|_| "/etc/kdyndns/config.toml".to_string());

    let cfg = AppConfig::from_file(&config_path).expect("Loading configuration failed");

    let config_arc = Arc::new(RwLock::new(cfg));
    let updater: Arc<dyn DnsUpdater> = Arc::new(NsupdateDnsUpdater::new());

    let state = AppState {
        config: Arc::clone(&config_arc),
        updater: updater.clone(),
    };

    // Reload-Task (SIGUSR1)
    let reload_state = state.clone();
    let config_path_clone = config_path.clone();
    tokio::spawn(async move {
        let mut sig =
            signal(SignalKind::user_defined1()).expect("Cannot create listener for SIGUSR1");
        loop {
            sig.recv().await;
            info!("Reload signal received (SIGUSR1)");
            match AppConfig::from_file(&config_path_clone) {
                Ok(new_cfg) => {
                    *reload_state.config.write().unwrap() = new_cfg;
                    info!("Reloading configuration successfull");
                }
                Err(e) => {
                    error!("Reloading configuration failed: {}", e);
                }
            }
        }
    });

    let _ = std::fs::remove_file(&socket_path);

    info!("KDynDNS is listening on unix socket: {}", socket_path);

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(state.clone()))
            .service(handlers::health)
            .service(handlers::update)
    })
    .bind_uds(&socket_path)?
    .run()
    .await
}
