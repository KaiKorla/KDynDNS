use actix_web::{App, HttpServer, web};
use listenfd::ListenFd;
use std::env;
use std::sync::{Arc, RwLock};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::Semaphore;
use tracing::{error, info};

mod auth;
mod config;
mod dns;
mod handlers;
mod security;

use crate::config::AppConfig;
use crate::dns::{DnsUpdater, Rfc2136DnsUpdater};
use crate::security::{AuthRateLimiter, default_auth_concurrency_limit};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<RwLock<AppConfig>>,
    pub updater: Arc<dyn DnsUpdater>,
    pub auth_limiter: Arc<AuthRateLimiter>,
    pub auth_slots: Arc<Semaphore>,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .without_time()
        .compact()
        .init();

    let config_path =
        env::var("DYNDNS_CONFIG").unwrap_or_else(|_| "/etc/kdyndns/config.toml".to_string());

    let cfg = AppConfig::from_file(&config_path).expect("Loading configuration failed");

    let config_arc = Arc::new(RwLock::new(cfg));
    let updater: Arc<dyn DnsUpdater> = Arc::new(Rfc2136DnsUpdater::new());
    let auth_limiter = Arc::new(AuthRateLimiter::default());
    let auth_slots = Arc::new(Semaphore::new(default_auth_concurrency_limit()));

    let state = AppState {
        config: Arc::clone(&config_arc),
        updater: updater.clone(),
        auth_limiter,
        auth_slots,
    };

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
                    info!("Reloading configuration successful");
                }
                Err(e) => {
                    error!("Reloading configuration failed: {}", e);
                }
            }
        }
    });

    let mut server = HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(state.clone()))
            .service(handlers::health)
            .service(handlers::update)
    });

    let mut listenfd = ListenFd::from_env();

    if let Some(listener) = listenfd.take_unix_listener(0)? {
        tracing::info!("using systemd-provided unix socket");
        server = server.listen_uds(listener)?;
    } else {
        tracing::warn!("no systemd socket received; binding unix socket directly");
        server = server.bind_uds("/run/kdyndns/kdyndns.sock")?;
    }

    info!(
        "KDynDNS is listening on unix socket: {:#?}",
        server.addrs_with_scheme()
    );

    server.run().await
}
