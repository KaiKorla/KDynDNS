use async_trait::async_trait;
use base64::prelude::*;
use hickory_client::client::{AsyncClient, ClientConnection, ClientHandle, Signer};
use hickory_client::op::ResponseCode;
use hickory_client::proto::rr::dnssec::tsig::TSigner;
use hickory_client::rr::rdata::tsig::TsigAlgorithm as HickoryTsigAlgorithm;
use hickory_client::rr::rdata::{A, AAAA};
use hickory_client::rr::{Name, RData, Record, RecordSet, RecordType};
use hickory_client::tcp::TcpClientConnection;
use hickory_client::udp::UdpClientConnection;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use thiserror::Error;
use tracing::info;

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DnsServerAddress {
    Tcp(SocketAddr),
    Udp(SocketAddr),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ParsedTsigAlgorithm {
    HmacMd5,
    Gss,
    HmacSha1,
    HmacSha224,
    HmacSha256,
    HmacSha256_128,
    HmacSha384,
    HmacSha384_192,
    HmacSha512,
    HmacSha512_256,
}

fn extract_quoted_value(line: &str) -> Option<String> {
    let (_, rest) = line.split_once('"')?;
    let (value, _) = rest.split_once('"')?;
    Some(value.to_string())
}

fn parse_tsig_algorithm(raw: &str) -> Option<ParsedTsigAlgorithm> {
    let normalized = raw.trim().trim_end_matches(';').trim_end_matches('.');
    let normalized = normalized.to_ascii_lowercase();

    match normalized.as_str() {
        "hmac-md5" => Some(ParsedTsigAlgorithm::HmacMd5),
        "gss-tsig" | "gss" => Some(ParsedTsigAlgorithm::Gss),
        "hmac-sha1" => Some(ParsedTsigAlgorithm::HmacSha1),
        "hmac-sha224" => Some(ParsedTsigAlgorithm::HmacSha224),
        "hmac-sha256" => Some(ParsedTsigAlgorithm::HmacSha256),
        "hmac-sha256-128" => Some(ParsedTsigAlgorithm::HmacSha256_128),
        "hmac-sha384" => Some(ParsedTsigAlgorithm::HmacSha384),
        "hmac-sha384-192" => Some(ParsedTsigAlgorithm::HmacSha384_192),
        "hmac-sha512" => Some(ParsedTsigAlgorithm::HmacSha512),
        "hmac-sha512-256" => Some(ParsedTsigAlgorithm::HmacSha512_256),
        _ => None,
    }
}

fn parse_tsig_key(content: &str) -> Result<(String, Vec<u8>, ParsedTsigAlgorithm), DnsError> {
    let mut key_name: Option<String> = None;
    let mut algorithm: Option<ParsedTsigAlgorithm> = None;
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

fn parse_tsig_key_file(path: &str) -> Result<(String, Vec<u8>, ParsedTsigAlgorithm), DnsError> {
    let content = fs::read_to_string(path)
        .map_err(|e| DnsError::UpdateFailed(format!("Reading TSIG key file failed: {}", e)))?;
    parse_tsig_key(&content)
}

fn parse_dns_server_address(server: &str) -> Result<DnsServerAddress, DnsError> {
    let (host, is_tcp) = if let Some(host) = server.strip_prefix("udp://") {
        (host, false)
    } else if let Some(host) = server.strip_prefix("tcp://") {
        (host, true)
    } else {
        (server, false)
    };

    let (host, port) = if let Some(host) = host.strip_prefix('[') {
        let (host, maybe_port) = host.rsplit_once(']').ok_or_else(|| {
            DnsError::UpdateFailed(format!("Invalid DNS server address: {}", server))
        })?;

        (
            host,
            maybe_port
                .rsplit_once(':')
                .map(|(_, port)| port)
                .unwrap_or("53"),
        )
    } else if let Some((host, port)) = host.rsplit_once(':') {
        (host, port)
    } else {
        (host, "53")
    };

    let addr = SocketAddr::new(
        host.parse().map_err(|_| {
            DnsError::UpdateFailed(format!("Invalid DNS server address: {}", server))
        })?,
        port.parse().map_err(|_| {
            DnsError::UpdateFailed(format!("Invalid DNS server address: {}", server))
        })?,
    );

    if is_tcp {
        Ok(DnsServerAddress::Tcp(addr))
    } else {
        Ok(DnsServerAddress::Udp(addr))
    }
}

fn to_hickory_tsig_algorithm(algorithm: ParsedTsigAlgorithm) -> HickoryTsigAlgorithm {
    match algorithm {
        ParsedTsigAlgorithm::HmacMd5 => HickoryTsigAlgorithm::HmacMd5,
        ParsedTsigAlgorithm::Gss => HickoryTsigAlgorithm::Gss,
        ParsedTsigAlgorithm::HmacSha1 => HickoryTsigAlgorithm::HmacSha1,
        ParsedTsigAlgorithm::HmacSha224 => HickoryTsigAlgorithm::HmacSha224,
        ParsedTsigAlgorithm::HmacSha256 => HickoryTsigAlgorithm::HmacSha256,
        ParsedTsigAlgorithm::HmacSha256_128 => HickoryTsigAlgorithm::HmacSha256_128,
        ParsedTsigAlgorithm::HmacSha384 => HickoryTsigAlgorithm::HmacSha384,
        ParsedTsigAlgorithm::HmacSha384_192 => HickoryTsigAlgorithm::HmacSha384_192,
        ParsedTsigAlgorithm::HmacSha512 => HickoryTsigAlgorithm::HmacSha512,
        ParsedTsigAlgorithm::HmacSha512_256 => HickoryTsigAlgorithm::HmacSha512_256,
    }
}

async fn connect_rfc2136_client(
    server: &str,
    key_name: &str,
    key_secret: &[u8],
    algorithm: ParsedTsigAlgorithm,
) -> Result<AsyncClient, DnsError> {
    let address = parse_dns_server_address(server)?;
    let signer = Arc::new(Signer::from(
        TSigner::new(
            key_secret.to_vec(),
            to_hickory_tsig_algorithm(algorithm),
            Name::from_ascii(key_name)
                .map_err(|e| DnsError::UpdateFailed(format!("Invalid TSIG key name: {}", e)))?,
            60,
        )
        .map_err(|e| DnsError::UpdateFailed(e.to_string()))?,
    ));

    match address {
        DnsServerAddress::Udp(addr) => {
            let connection = UdpClientConnection::new(addr)
                .map_err(|e| DnsError::UpdateFailed(e.to_string()))?;
            let (client, background) = AsyncClient::connect(connection.new_stream(Some(signer)))
                .await
                .map_err(|e| DnsError::UpdateFailed(e.to_string()))?;
            tokio::spawn(background);
            Ok(client)
        }
        DnsServerAddress::Tcp(addr) => {
            let connection = TcpClientConnection::new(addr)
                .map_err(|e| DnsError::UpdateFailed(e.to_string()))?;
            let (client, background) = AsyncClient::connect(connection.new_stream(Some(signer)))
                .await
                .map_err(|e| DnsError::UpdateFailed(e.to_string()))?;
            tokio::spawn(background);
            Ok(client)
        }
    }
}

fn check_update_response(response_code: ResponseCode) -> Result<(), DnsError> {
    if response_code == ResponseCode::NoError {
        Ok(())
    } else {
        Err(DnsError::UpdateFailed(response_code.to_string()))
    }
}

async fn delete_address_rrsets(
    client: &mut AsyncClient,
    fqdn: &str,
    zone: &str,
) -> Result<(), DnsError> {
    let fqdn_name =
        Name::from_str_relaxed(fqdn).map_err(|e| DnsError::UpdateFailed(e.to_string()))?;
    let zone_name =
        Name::from_str_relaxed(zone).map_err(|e| DnsError::UpdateFailed(e.to_string()))?;

    for record_type in [RecordType::A, RecordType::AAAA] {
        let delete_record = Record::with(fqdn_name.clone(), record_type, 0);
        let response = client
            .delete_rrset(delete_record, zone_name.clone())
            .await
            .map_err(|e| DnsError::UpdateFailed(e.to_string()))?;
        check_update_response(response.response_code())?;
    }

    Ok(())
}

async fn append_ipv4_rrset(
    client: &mut AsyncClient,
    fqdn: &str,
    zone: &str,
    ttl: u32,
    ip: Ipv4Addr,
) -> Result<(), DnsError> {
    let fqdn_name =
        Name::from_str_relaxed(fqdn).map_err(|e| DnsError::UpdateFailed(e.to_string()))?;
    let zone_name =
        Name::from_str_relaxed(zone).map_err(|e| DnsError::UpdateFailed(e.to_string()))?;
    let mut rrset = RecordSet::with_ttl(fqdn_name, RecordType::A, ttl);
    rrset.add_rdata(RData::A(A::from(ip)));

    let response = client
        .append(rrset, zone_name, false)
        .await
        .map_err(|e| DnsError::UpdateFailed(e.to_string()))?;
    check_update_response(response.response_code())
}

async fn append_ipv6_rrset(
    client: &mut AsyncClient,
    fqdn: &str,
    zone: &str,
    ttl: u32,
    ip: Ipv6Addr,
) -> Result<(), DnsError> {
    let fqdn_name =
        Name::from_str_relaxed(fqdn).map_err(|e| DnsError::UpdateFailed(e.to_string()))?;
    let zone_name =
        Name::from_str_relaxed(zone).map_err(|e| DnsError::UpdateFailed(e.to_string()))?;
    let mut rrset = RecordSet::with_ttl(fqdn_name, RecordType::AAAA, ttl);
    rrset.add_rdata(RData::AAAA(AAAA::from(ip)));

    let response = client
        .append(rrset, zone_name, false)
        .await
        .map_err(|e| DnsError::UpdateFailed(e.to_string()))?;
    check_update_response(response.response_code())
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
            "DNS update via hickory-client (RFC2136): user={}, zone={}, fqdn={}, ipv4={:?}, ipv6={:?}",
            user.username, zone, fqdn, ipv4, ipv6
        );

        let mut client =
            connect_rfc2136_client(&user.server, &key_name, &key_secret, tsig_algorithm).await?;

        delete_address_rrsets(&mut client, &fqdn, &zone).await?;

        if let Some(ip) = ipv4 {
            append_ipv4_rrset(&mut client, &fqdn, &zone, ttl, ip).await?;
        }

        if let Some(ip) = ipv6 {
            append_ipv6_rrset(&mut client, &fqdn, &zone, ttl, ip).await?;
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
    fn parse_udp_server_with_default_port() {
        let addr = parse_dns_server_address("127.0.0.1").unwrap();
        assert_eq!(addr, DnsServerAddress::Udp("127.0.0.1:53".parse().unwrap()));
    }

    #[test]
    fn parse_tcp_server_with_explicit_port() {
        let addr = parse_dns_server_address("tcp://127.0.0.1:5353").unwrap();
        assert_eq!(
            addr,
            DnsServerAddress::Tcp("127.0.0.1:5353".parse().unwrap())
        );
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
        assert!(matches!(alg, ParsedTsigAlgorithm::HmacSha256));
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
