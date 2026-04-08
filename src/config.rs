use serde::Deserialize;
use std::collections::HashSet;
use std::error::Error;
use std::fs;
use std::io;

use crate::auth::validate_password_hash;
use crate::dns::{normalize_fqdn, validate_dns_server_address, validate_tsig_key_file};

#[derive(Debug, Clone, Deserialize)]
pub struct UserConfig {
    pub server: String,
    pub tsig_key_path: String,
    pub username: String,
    pub password_hash: String,
    pub allowed_hosts: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub users: Vec<UserConfig>,
}

impl AppConfig {
    pub fn from_file(path: &str) -> Result<Self, Box<dyn Error>> {
        let content = fs::read_to_string(path)?;
        let mut cfg: AppConfig = toml::from_str(&content)?;
        cfg.validate_and_normalize()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok(cfg)
    }

    pub fn find_user(&self, username: &str) -> Option<&UserConfig> {
        self.users.iter().find(|u| u.username == username)
    }

    pub(crate) fn validate_and_normalize(&mut self) -> Result<(), String> {
        if self.users.is_empty() {
            return Err("At least one user must be configured".to_string());
        }

        let mut seen_usernames = HashSet::new();

        for user in &mut self.users {
            let username = user.username.trim();
            if username.is_empty() {
                return Err("User username must not be empty".to_string());
            }

            let username_key = username.to_ascii_lowercase();
            if !seen_usernames.insert(username_key) {
                return Err(format!("Duplicate username '{}'", username));
            }

            validate_password_hash(&user.password_hash)
                .map_err(|e| format!("User '{}': {}", username, e))?;
            validate_dns_server_address(&user.server)
                .map_err(|e| format!("User '{}': {}", username, e))?;
            validate_tsig_key_file(&user.tsig_key_path)
                .map_err(|e| format!("User '{}': {}", username, e))?;

            if user.allowed_hosts.is_empty() {
                return Err(format!(
                    "User '{}': allowed_hosts must not be empty",
                    username
                ));
            }

            let mut normalized_hosts = Vec::with_capacity(user.allowed_hosts.len());
            let mut seen_hosts = HashSet::new();

            for allowed_host in &user.allowed_hosts {
                let normalized = normalize_fqdn(allowed_host).map_err(|_| {
                    format!(
                        "User '{}': invalid allowed host '{}'",
                        username, allowed_host
                    )
                })?;

                if seen_hosts.insert(normalized.clone()) {
                    normalized_hosts.push(normalized);
                }
            }

            user.username = username.to_string();
            user.allowed_hosts = normalized_hosts;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::time::{SystemTime, UNIX_EPOCH};

    const VALID_PASSWORD_HASH: &str = "$argon2id$v=19$m=65536,t=3,p=1$WnJ1TFZNZEQ0QTR2ZTBJWmU1U3VRZz09$xUlVAT+VaNcyoUWHkG7kByZSepDKwJnzFScqJUmYlg8";

    fn write_test_tsig_key() -> String {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = env::temp_dir().join(format!("kdyndns-test-{}.key", unique));

        fs::write(
            &path,
            r#"
key "dyn-key" {
    algorithm hmac-sha256;
    secret "dGVzdA==";
};
"#,
        )
        .unwrap();

        path.to_string_lossy().into_owned()
    }

    fn build_config(tsig_key_path: String) -> AppConfig {
        AppConfig {
            users: vec![UserConfig {
                server: "udp://127.0.0.1:53".into(),
                tsig_key_path,
                username: "user1".into(),
                password_hash: VALID_PASSWORD_HASH.into(),
                allowed_hosts: vec!["Test.Example.com".into()],
            }],
        }
    }

    #[test]
    fn validate_and_normalize_normalizes_allowed_hosts() {
        let tsig_key_path = write_test_tsig_key();
        let mut cfg = build_config(tsig_key_path.clone());

        cfg.validate_and_normalize().unwrap();
        assert_eq!(
            cfg.users[0].allowed_hosts,
            vec!["test.example.com.".to_string()]
        );

        let _ = fs::remove_file(tsig_key_path);
    }

    #[test]
    fn validate_and_normalize_rejects_invalid_password_hash() {
        let tsig_key_path = write_test_tsig_key();
        let mut cfg = build_config(tsig_key_path.clone());
        cfg.users[0].password_hash = "invalid".into();

        let err = cfg.validate_and_normalize().unwrap_err();
        assert!(err.contains("Invalid password hash"));

        let _ = fs::remove_file(tsig_key_path);
    }
}
