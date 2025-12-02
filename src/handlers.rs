use actix_web::{HttpRequest, HttpResponse, Responder, get, web};
use serde::Deserialize;
use std::net::{Ipv4Addr, Ipv6Addr};
use tracing::{info, warn};

use crate::AppState;
use crate::auth::{parse_basic_auth, verify_user};
use crate::dns::DnsError;

#[derive(Deserialize)]
pub struct UpdateQuery {
    pub host: String,
    pub ip4: Option<String>,
    pub ip6: Option<String>,
}

#[get("/health")]
pub async fn health() -> impl Responder {
    HttpResponse::Ok().body("OK")
}

#[get("/update")]
pub async fn update(
    req: HttpRequest,
    query: web::Query<UpdateQuery>,
    state: web::Data<AppState>,
) -> impl Responder {
    let (username, password) = match parse_basic_auth(&req) {
        Some(c) => c,
        None => {
            return HttpResponse::Unauthorized()
                .append_header(("WWW-Authenticate", "Basic realm=\"KDynDNS\""))
                .body("Unauthorized");
        }
    };

    let cfg = state.config.read().unwrap();

    let user = match verify_user(&cfg, &username, &password) {
        Some(u) => u,
        None => {
            warn!("Auth failed for user '{}'", username);
            return HttpResponse::Unauthorized().body("Invalid credentials");
        }
    };

    // Host normalisieren (immer FQDN mit Punkt)
    let host_norm = if query.host.ends_with('.') {
        query.host.trim().to_string()
    } else {
        format!("{}.", query.host.trim())
    };

    if !user.allowed_hosts.iter().any(|h| h == &host_norm) {
        warn!(
            "User '{}' is not allowed to update host '{}'",
            username, host_norm
        );
        return HttpResponse::Forbidden().body("Host not allowed");
    }

    if query.ip4.is_none() && query.ip6.is_none() {
        return HttpResponse::BadRequest().body("At least one of ip4 or ip6 required");
    }

    let ip4: Option<Ipv4Addr> = match &query.ip4 {
        Some(v) if !v.trim().is_empty() => match v.trim().parse() {
            Ok(ip) => Some(ip),
            Err(_) => return HttpResponse::BadRequest().body("Invalid ip4 format"),
        },
        _ => None,
    };

    let ip6: Option<Ipv6Addr> = match &query.ip6 {
        Some(v) if !v.trim().is_empty() => match v.trim().parse() {
            Ok(ip) => Some(ip),
            Err(_) => return HttpResponse::BadRequest().body("Invalid ip6 format"),
        },
        _ => None,
    };

    if ip4.is_none() && ip6.is_none() {
        return HttpResponse::BadRequest().body("ip4/ip6 empty or invalid");
    }

    info!(
        "Update request: user={}, host={}, ip4={:?}, ip6={:?}",
        username, host_norm, ip4, ip6
    );

    match state.updater.update_records(user, &host_norm, ip4, ip6) {
        Ok(()) => HttpResponse::Ok().body("OK"),
        Err(DnsError::InvalidHost) => HttpResponse::BadRequest().body("Invalid host"),
        Err(DnsError::UpdateFailed(e)) => {
            warn!("DNS update failed for {}: {}", host_norm, e);
            HttpResponse::InternalServerError().body("DNS update failed")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{App, test};
    use argon2::PasswordHasher;
    use base64::prelude::*;
    use password_hash::SaltString;
    use rand::rngs::OsRng;
    use std::sync::{Arc, RwLock};

    use crate::AppState;
    use crate::config::{AppConfig, UserConfig};
    use crate::dns::MockDnsUpdater;

    fn build_test_state(should_fail: bool) -> AppState {
        // Passwort "secret"
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = argon2::Argon2::default();
        let hash = argon2.hash_password(b"secret", &salt).unwrap().to_string();

        let cfg = AppConfig {
            users: vec![UserConfig {
                server: "127.0.0.1".into(),
                tsig_key_path: "/dev/null".into(),
                username: "user".into(),
                password_hash: hash,
                allowed_hosts: vec!["test.example.com.".into()],
            }],
        };

        let updater = MockDnsUpdater {
            should_fail,
            ..Default::default()
        };

        AppState {
            config: Arc::new(RwLock::new(cfg)),
            updater: Arc::new(updater),
        }
    }

    #[actix_web::test]
    async fn health_works() {
        let state = build_test_state(false);
        let app =
            test::init_service(App::new().app_data(web::Data::new(state)).service(health)).await;

        let req = test::TestRequest::get().uri("/health").to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }

    #[actix_web::test]
    async fn update_requires_auth() {
        let state = build_test_state(false);
        let app =
            test::init_service(App::new().app_data(web::Data::new(state)).service(update)).await;

        let req = test::TestRequest::get()
            .uri("/update?host=test.example.com.&ip4=1.2.3.4")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 401);
    }

    #[actix_web::test]
    async fn update_success_with_mock_dns() {
        let state = build_test_state(false);
        let app =
            test::init_service(App::new().app_data(web::Data::new(state)).service(update)).await;

        let token = BASE64_STANDARD.encode("user:secret");
        let req = test::TestRequest::get()
            .uri("/update?host=test.example.com.&ip4=1.2.3.4")
            .append_header(("Authorization", format!("Basic {}", token)))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
    }

    #[actix_web::test]
    async fn update_dns_failure_propagates_500() {
        let state = build_test_state(true);
        let app =
            test::init_service(App::new().app_data(web::Data::new(state)).service(update)).await;

        let token = BASE64_STANDARD.encode("user:secret");
        let req = test::TestRequest::get()
            .uri("/update?host=test.example.com.&ip4=1.2.3.4")
            .append_header(("Authorization", format!("Basic {}", token)))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 500);
    }
}
