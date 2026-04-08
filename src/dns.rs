use async_trait::async_trait;
use base64::prelude::*;
use hickory_client::client::{AsyncClient, ClientConnection, ClientHandle, Signer};
use hickory_client::op::ResponseCode;
use hickory_client::proto::rr::dnssec::tsig::TSigner;
use hickory_client::rr::rdata::tsig::TsigAlgorithm as HickoryTsigAlgorithm;
use hickory_client::rr::rdata::{A, AAAA};
use hickory_client::rr::{DNSClass, Name, RData, Record, RecordSet, RecordType};
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

pub fn normalize_fqdn(host: &str) -> Result<String, DnsError> {
    let trimmed = host.trim();
    let without_root = trimmed.trim_end_matches('.');

    if without_root.is_empty() {
        return Err(DnsError::InvalidHost);
    }

    let labels: Vec<&str> = without_root.split('.').collect();
    if labels.len() < 2 || labels.iter().any(|label| label.is_empty()) {
        return Err(DnsError::InvalidHost);
    }

    let fqdn = format!("{}.", without_root.to_ascii_lowercase());
    Name::from_str_relaxed(&fqdn).map_err(|_| DnsError::InvalidHost)?;

    Ok(fqdn)
}

fn zone_candidates(fqdn: &str) -> Result<Vec<String>, DnsError> {
    let normalized = normalize_fqdn(fqdn)?;
    let labels: Vec<&str> = normalized.trim_end_matches('.').split('.').collect();

    Ok((0..labels.len() - 1)
        .map(|start| format!("{}.", labels[start..].join(".")))
        .collect())
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
    HmacSha256,
    HmacSha384,
    HmacSha512,
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
        "hmac-sha256" => Some(ParsedTsigAlgorithm::HmacSha256),
        "hmac-sha384" => Some(ParsedTsigAlgorithm::HmacSha384),
        "hmac-sha512" => Some(ParsedTsigAlgorithm::HmacSha512),
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
        ParsedTsigAlgorithm::HmacSha256 => HickoryTsigAlgorithm::HmacSha256,
        ParsedTsigAlgorithm::HmacSha384 => HickoryTsigAlgorithm::HmacSha384,
        ParsedTsigAlgorithm::HmacSha512 => HickoryTsigAlgorithm::HmacSha512,
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

fn parse_name(value: &str) -> Result<Name, DnsError> {
    Name::from_str_relaxed(value).map_err(|e| DnsError::UpdateFailed(e.to_string()))
}

async fn discover_authoritative_zone(
    client: &mut AsyncClient,
    fqdn: &str,
) -> Result<String, DnsError> {
    for candidate in zone_candidates(fqdn)? {
        let response = client
            .query(parse_name(&candidate)?, DNSClass::IN, RecordType::SOA)
            .await
            .map_err(|e| DnsError::UpdateFailed(e.to_string()))?;

        if response.response_code() == ResponseCode::NoError
            && response
                .answers()
                .iter()
                .any(|answer| answer.record_type() == RecordType::SOA)
        {
            return Ok(candidate);
        }

        if matches!(
            response.response_code(),
            ResponseCode::NoError | ResponseCode::NXDomain
        ) {
            if let Some(soa) = response.soa() {
                let zone = normalize_fqdn(&soa.name().to_utf8())?;
                if fqdn.ends_with(&zone) {
                    return Ok(zone);
                }
            }
        }
    }

    Err(DnsError::UpdateFailed(format!(
        "Could not determine authoritative zone for {}",
        fqdn
    )))
}

async fn delete_rrset(
    client: &mut AsyncClient,
    fqdn: &str,
    zone: &str,
    record_type: RecordType,
) -> Result<(), DnsError> {
    let fqdn_name = parse_name(fqdn)?;
    let zone_name = parse_name(zone)?;

    let delete_record = Record::with(fqdn_name, record_type, 0);
    let response = client
        .delete_rrset(delete_record, zone_name)
        .await
        .map_err(|e| DnsError::UpdateFailed(e.to_string()))?;
    check_update_response(response.response_code())
}

async fn append_ipv4_rrset(
    client: &mut AsyncClient,
    fqdn: &str,
    zone: &str,
    ttl: u32,
    ip: Ipv4Addr,
) -> Result<(), DnsError> {
    let fqdn_name = parse_name(fqdn)?;
    let zone_name = parse_name(zone)?;
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
    let fqdn_name = parse_name(fqdn)?;
    let zone_name = parse_name(zone)?;
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
        let fqdn = normalize_fqdn(host)?;
        let ttl = 60;
        let (key_name, key_secret, tsig_algorithm) = parse_tsig_key_file(&user.tsig_key_path)?;

        let mut client =
            connect_rfc2136_client(&user.server, &key_name, &key_secret, tsig_algorithm).await?;
        let zone = discover_authoritative_zone(&mut client, &fqdn).await?;

        info!(
            "DNS update via hickory-client (RFC2136): user={}, zone={}, fqdn={}, ipv4={:?}, ipv6={:?}",
            user.username, zone, fqdn, ipv4, ipv6
        );

        if let Some(ip) = ipv4 {
            delete_rrset(&mut client, &fqdn, &zone, RecordType::A).await?;
            append_ipv4_rrset(&mut client, &fqdn, &zone, ttl, ip).await?;
        }

        if let Some(ip) = ipv6 {
            delete_rrset(&mut client, &fqdn, &zone, RecordType::AAAA).await?;
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
    fn normalize_fqdn_lowercases_and_adds_root_label() {
        let fqdn = normalize_fqdn("MyHost.Domain.Tld").unwrap();
        assert_eq!(fqdn, "myhost.domain.tld.");
    }

    #[test]
    fn zone_candidates_include_more_specific_suffixes() {
        let candidates = zone_candidates("host.dyn.example.com.").unwrap();
        assert_eq!(
            candidates,
            vec![
                "host.dyn.example.com.".to_string(),
                "dyn.example.com.".to_string(),
                "example.com.".to_string()
            ]
        );
    }

    #[test]
    fn zone_candidates_for_zone_apex_return_single_candidate() {
        let candidates = zone_candidates("example.com").unwrap();
        assert_eq!(candidates, vec!["example.com.".to_string()]);
    }

    #[test]
    fn invalid_host_too_short() {
        let res = normalize_fqdn("invalid");
        assert!(matches!(res, Err(DnsError::InvalidHost)));
    }

    #[test]
    fn invalid_host_empty() {
        let res = normalize_fqdn("");
        assert!(matches!(res, Err(DnsError::InvalidHost)));
    }

    #[test]
    fn invalid_host_with_empty_label() {
        let res = normalize_fqdn("host..example.com");
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

    #[test]
    fn parse_tsig_key_rejects_unsupported_but_known_algorithms() {
        let content = r#"
key "dyn-key" {
    algorithm hmac-sha1;
    secret "dGVzdA==";
};
"#;

        let res = parse_tsig_key(content);
        assert!(matches!(res, Err(DnsError::UpdateFailed(_))));
    }
}
