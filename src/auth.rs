use actix_web::HttpRequest;
use argon2::{Argon2, PasswordVerifier};
use base64::prelude::*;
use password_hash::PasswordHash;
use tracing::warn;

use crate::config::{AppConfig, UserConfig};

pub fn parse_basic_auth(req: &HttpRequest) -> Option<(String, String)> {
    let header = req.headers().get("Authorization")?;
    let header_str = header.to_str().ok()?;

    if !header_str.starts_with("Basic ") {
        return None;
    }

    let b64 = &header_str[6..];
    let decoded = BASE64_STANDARD.decode(b64).ok();
    let decoded_str = String::from_utf8(decoded?).ok()?;

    let mut parts = decoded_str.splitn(2, ':');
    let user = parts.next()?.to_string();
    let pass = parts.next().unwrap_or("").to_string();

    Some((user, pass))
}

pub fn verify_user<'a>(
    cfg: &'a AppConfig,
    username: &str,
    password: &str,
) -> Option<&'a UserConfig> {
    let user = cfg.find_user(username)?;

    let parsed_hash = match PasswordHash::new(&user.password_hash) {
        Ok(h) => h,
        Err(e) => {
            warn!("Error while parsing the password for {}: {}", username, e);
            return None;
        }
    };

    if Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
    {
        Some(user)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AppConfig, UserConfig};
    use actix_web::test::TestRequest;
    use argon2::PasswordHasher;
    use password_hash::SaltString;
    use rand::rngs::OsRng;

    fn build_test_config() -> AppConfig {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let hash = argon2.hash_password(b"secret", &salt).unwrap().to_string();

        AppConfig {
            users: vec![UserConfig {
                server: "127.0.0.1".into(),
                tsig_key_path: "/dev/null".into(),
                username: "test".into(),
                password_hash: hash,
                allowed_hosts: vec!["host.example.com.".into()],
            }],
        }
    }

    #[test]
    fn verify_correct_password() {
        let cfg = build_test_config();
        let user = verify_user(&cfg, "test", "secret");
        assert!(user.is_some());
    }

    #[test]
    fn reject_wrong_password() {
        let cfg = build_test_config();
        let user = verify_user(&cfg, "test", "wrong");
        assert!(user.is_none());
    }

    #[test]
    fn reject_unknown_user() {
        let cfg = build_test_config();
        let user = verify_user(&cfg, "nobody", "secret");
        assert!(user.is_none());
    }

    #[test]
    fn parse_basic_auth_header() {
        let encoded = BASE64_STANDARD.encode("test:secret");
        let header_val = format!("Basic {}", encoded);

        let req = TestRequest::get()
            .insert_header(("Authorization", header_val))
            .to_http_request();

        let res = parse_basic_auth(&req);
        assert!(res.is_some());
        let (u, p) = res.unwrap();
        assert_eq!(u, "test");
        assert_eq!(p, "secret");
    }
}
