use serde::Deserialize;
use std::error::Error;
use std::fs;

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
        let cfg: AppConfig = toml::from_str(&content)?;
        Ok(cfg)
    }

    pub fn find_user(&self, username: &str) -> Option<&UserConfig> {
        self.users.iter().find(|u| u.username == username)
    }
}
