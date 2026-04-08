use async_trait::async_trait;
use base64::prelude::*;
use dns_update::{
    DnsRecord, DnsRecordType, DnsUpdater as ExternalDnsUpdater, Error as DnsUpdateError,
    TsigAlgorithm,
};
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use thiserror::Error;
use tracing::{info, warn};

use crate::config::UserConfig;

#[derive(Error, Debug)]
pub enum DnsError {
    #[error("Invalid host")]
    InvalidHost,

    #[error("DNS update failed: {0}")]
    UpdateFailed(String),
}

#[async_trait]
pub trait DnsUpdater: Send + Sync {
    async fn update_records(
        &self,
        user: &UserConfig,
        host: &str,
        ipv4: Option<Ipv4Addr>,
        ipv6: Option<Ipv6Addr>,
    ) -> Result<(), DnsError>;
}

/// myhost.domain.tld → zone = domain.tld. , fqdn = myhost.domain.tld.
pub fn derive_zone_and_fqdn(host: &str) -> Result<(String, String), DnsError> {
    let fqdn = if host.ends_with('.') {
        host.to_string()
    } else {
        format!("{}.", host)
    };

    let parts: Vec<&str> = fqdn.trim_end_matches('.').split('.').collect();

    if parts.len() < 2 {
        return Err(DnsError::InvalidHost);
    }

    let zone = if parts.len() >= 3 {
        format!("{}.{}.", parts[parts.len() - 2], parts[parts.len() - 1])
    } else {
        format!("{}.{}.", parts[0], parts[1])
    };

    Ok((zone, fqdn))
}

pub struct Rfc2136DnsUpdater;

impl Rfc2136DnsUpdater {
    pub fn new() -> Self {
        Rfc2136DnsUpdater
    }
}

fn extract_quoted_value(line: &str) -> Option<String> {
    let (_, rest) = line.split_once('"')?;
    let (value, _) = rest.split_once('"')?;
    Some(value.to_string())
}

fn parse_tsig_algorithm(raw: &str) -> Option<TsigAlgorithm> {
    let normalized = raw.trim().trim_end_matches(';').trim_end_matches('.');
    let normalized = normalized.to_ascii_lowercase();

    match normalized.as_str() {
        "hmac-md5" => Some(TsigAlgorithm::HmacMd5),
        "gss-tsig" | "gss" => Some(TsigAlgorithm::Gss),
        "hmac-sha1" => Some(TsigAlgorithm::HmacSha1),
        "hmac-sha224" => Some(TsigAlgorithm::HmacSha224),
        "hmac-sha256" => Some(TsigAlgorithm::HmacSha256),
        "hmac-sha256-128" => Some(TsigAlgorithm::HmacSha256_128),
        "hmac-sha384" => Some(TsigAlgorithm::HmacSha384),
        "hmac-sha384-192" => Some(TsigAlgorithm::HmacSha384_192),
        "hmac-sha512" => Some(TsigAlgorithm::HmacSha512),
        "hmac-sha512-256" => Some(TsigAlgorithm::HmacSha512_256),
        _ => None,
    }
}

fn parse_tsig_key(content: &str) -> Result<(String, Vec<u8>, TsigAlgorithm), DnsError> {
    let mut key_name: Option<String> = None;
    let mut algorithm: Option<TsigAlgorithm> = None;
    let mut secret_b64: Option<String> = None;

    for line in content.lines() {
        let line = line.trim();

        if key_name.is_none() && line.starts_with("key ") {
            key_name = extract_quoted_value(line);
            continue;
        }

        if algorithm.is_none() && line.starts_with("algorithm ") {
            let raw = line
                .trim_start_matches("algorithm")
                .trim()
                .trim_end_matches(';');
            algorithm = parse_tsig_algorithm(raw);
            continue;
        }

        if secret_b64.is_none() && line.starts_with("secret ") {
            secret_b64 = extract_quoted_value(line);
        }
    }

    let key_name = key_name
        .ok_or_else(|| DnsError::UpdateFailed("TSIG key name missing in key file".to_string()))?;
    let algorithm = algorithm.ok_or_else(|| {
        DnsError::UpdateFailed("TSIG algorithm missing or unsupported".to_string())
    })?;
    let secret_b64 = secret_b64
        .ok_or_else(|| DnsError::UpdateFailed("TSIG secret missing in key file".to_string()))?;

    let secret = BASE64_STANDARD
        .decode(secret_b64.as_bytes())
        .map_err(|e| DnsError::UpdateFailed(format!("Invalid TSIG base64 secret: {}", e)))?;

    Ok((key_name, secret, algorithm))
}

fn parse_tsig_key_file(path: &str) -> Result<(String, Vec<u8>, TsigAlgorithm), DnsError> {
    let content = fs::read_to_string(path)
        .map_err(|e| DnsError::UpdateFailed(format!("Reading TSIG key file failed: {}", e)))?;
    parse_tsig_key(&content)
}

fn is_absent_record_error(err: &DnsUpdateError) -> bool {
    matches!(err, DnsUpdateError::NotFound)
        || matches!(err, DnsUpdateError::Response(code) if code.contains("NX"))
}

#[async_trait]
impl DnsUpdater for Rfc2136DnsUpdater {
    async fn update_records(
        &self,
        user: &UserConfig,
        host: &str,
        ipv4: Option<Ipv4Addr>,
        ipv6: Option<Ipv6Addr>,
    ) -> Result<(), DnsError> {
        let (zone, fqdn) = derive_zone_and_fqdn(host)?;
        let ttl = 60;
        let (key_name, key_secret, tsig_algorithm) = parse_tsig_key_file(&user.tsig_key_path)?;

        info!(
            "DNS update via dns-update (RFC2136): user={}, zone={}, fqdn={}, ipv4={:?}, ipv6={:?}",
            user.username, zone, fqdn, ipv4, ipv6
        );

        let updater = ExternalDnsUpdater::new_rfc2136_tsig(
            &user.server,
            key_name,
            key_secret,
            tsig_algorithm,
        )
        .map_err(|e| DnsError::UpdateFailed(e.to_string()))?;

        if let Err(e) = updater.delete(&fqdn, &zone, DnsRecordType::A).await {
            if !is_absent_record_error(&e) {
                warn!("Deleting previous DNS records failed for {}: {}", fqdn, e);
                return Err(DnsError::UpdateFailed(e.to_string()));
            }
        }

        if let Some(ip) = ipv4 {
            updater
                .create(&fqdn, DnsRecord::A { content: ip }, ttl, &zone)
                .await
                .map_err(|e| DnsError::UpdateFailed(e.to_string()))?;
        }

        if let Some(ip) = ipv6 {
            updater
                .create(&fqdn, DnsRecord::AAAA { content: ip }, ttl, &zone)
                .await
                .map_err(|e| DnsError::UpdateFailed(e.to_string()))?;
        }

        Ok(())
    }
}

#[cfg(test)]
pub struct MockDnsUpdater {
    pub should_fail: bool,
    pub calls: std::sync::Mutex<Vec<(String, Option<Ipv4Addr>, Option<Ipv6Addr>)>>,
}

#[cfg(test)]
impl Default for MockDnsUpdater {
    fn default() -> Self {
        Self {
            should_fail: false,
            calls: std::sync::Mutex::new(Vec::new()),
        }
    }
}

#[cfg(test)]
#[async_trait]
impl DnsUpdater for MockDnsUpdater {
    async fn update_records(
        &self,
        _user: &UserConfig,
        host: &str,
        ipv4: Option<Ipv4Addr>,
        ipv6: Option<Ipv6Addr>,
    ) -> Result<(), DnsError> {
        self.calls
            .lock()
            .unwrap()
            .push((host.to_string(), ipv4, ipv6));
        if self.should_fail {
            Err(DnsError::UpdateFailed("mock failure".into()))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns_update::TsigAlgorithm;

    #[test]
    fn derive_zone_three_parts() {
        let (zone, fqdn) = derive_zone_and_fqdn("myhost.domain.tld").unwrap();
        assert_eq!(zone, "domain.tld.");
        assert_eq!(fqdn, "myhost.domain.tld.");
    }

    #[test]
    fn derive_zone_trailing_dot() {
        let (zone, fqdn) = derive_zone_and_fqdn("myhost.domain.tld.").unwrap();
        assert_eq!(zone, "domain.tld.");
        assert_eq!(fqdn, "myhost.domain.tld.");
    }

    #[test]
    fn derive_zone_two_parts() {
        let (zone, fqdn) = derive_zone_and_fqdn("example.com").unwrap();
        assert_eq!(zone, "example.com.");
        assert_eq!(fqdn, "example.com.");
    }

    #[test]
    fn invalid_host_too_short() {
        let res = derive_zone_and_fqdn("invalid");
        assert!(matches!(res, Err(DnsError::InvalidHost)));
    }

    #[test]
    fn invalid_host_empty() {
        let res = derive_zone_and_fqdn("");
        assert!(matches!(res, Err(DnsError::InvalidHost)));
    }

    #[test]
    fn parse_tsig_key_ok() {
        let content = r#"
key "dyn-key" {
    algorithm hmac-sha256;
    secret "dGVzdA==";
};
"#;

        let (name, secret, alg) = parse_tsig_key(content).unwrap();
        assert_eq!(name, "dyn-key");
        assert_eq!(secret, b"test");
        assert!(matches!(alg, TsigAlgorithm::HmacSha256));
    }

    #[test]
    fn parse_tsig_key_invalid_algorithm() {
        let content = r#"
key "dyn-key" {
    algorithm unsupported-algorithm;
    secret "dGVzdA==";
};
"#;

        let res = parse_tsig_key(content);
        assert!(matches!(res, Err(DnsError::UpdateFailed(_))));
    }
}
