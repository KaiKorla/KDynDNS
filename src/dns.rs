use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::{Command, Stdio};
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

pub trait DnsUpdater: Send + Sync {
    fn update_records(
        &self,
        user: &UserConfig,
        host: &str,
        ip4: Option<Ipv4Addr>,
        ip6: Option<Ipv6Addr>,
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

pub struct NsupdateDnsUpdater;

impl NsupdateDnsUpdater {
    pub fn new() -> Self {
        NsupdateDnsUpdater
    }
}

impl DnsUpdater for NsupdateDnsUpdater {
    fn update_records(
        &self,
        user: &UserConfig,
        host: &str,
        ip4: Option<Ipv4Addr>,
        ip6: Option<Ipv6Addr>,
    ) -> Result<(), DnsError> {
        let (zone, fqdn) = derive_zone_and_fqdn(host)?;

        let ttl = 60;

        info!(
            "DNS update via nsupdate: user={}, zone={}, fqdn={}, ip4={:?}, ip6={:?}",
            user.username, zone, fqdn, ip4, ip6
        );

        let mut cmd = Command::new("nsupdate")
            .arg("-k")
            .arg(&user.tsig_key_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| DnsError::UpdateFailed(e.to_string()))?;

        {
            let stdin = cmd
                .stdin
                .as_mut()
                .ok_or_else(|| DnsError::UpdateFailed("stdin unavailable".into()))?;

            writeln!(stdin, "server {}", user.server).unwrap();
            writeln!(stdin, "zone {}", zone).unwrap();

            // Immer alles löschen
            writeln!(stdin, "update delete {} A", fqdn).unwrap();
            writeln!(stdin, "update delete {} AAAA", fqdn).unwrap();

            // Neue Einträge setzen
            if let Some(ip) = ip4 {
                writeln!(stdin, "update add {} {} A {}", fqdn, ttl, ip).unwrap();
            }
            if let Some(ip) = ip6 {
                writeln!(stdin, "update add {} {} AAAA {}", fqdn, ttl, ip).unwrap();
            }

            writeln!(stdin, "send").unwrap();
        }

        let output = cmd
            .wait_with_output()
            .map_err(|e| DnsError::UpdateFailed(e.to_string()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("nsupdate stderr: {}", stderr);
            return Err(DnsError::UpdateFailed(stderr.into_owned()));
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
impl DnsUpdater for MockDnsUpdater {
    fn update_records(
        &self,
        _user: &UserConfig,
        host: &str,
        ip4: Option<Ipv4Addr>,
        ip6: Option<Ipv6Addr>,
    ) -> Result<(), DnsError> {
        self.calls
            .lock()
            .unwrap()
            .push((host.to_string(), ip4, ip6));
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
}
