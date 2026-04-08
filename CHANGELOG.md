# Changelog

All notable changes to this project will be documented in this file.

The format is based on <https://keepachangelog.com/en/1.0.0/>

## [Unreleased]

### Added

No new features.

### Changed

- Replaced shell-based DNS updates with the `dns-update` crate (RFC 2136 + TSIG).
- Internal DNS updater interface is now async; request handling awaits DNS updates directly.
- TSIG credentials are now parsed from the local key file and passed to the RFC 2136 client.
- Updated examples/docs to match the new DNS server URI style (for example `udp://127.0.0.1:53`) and `DYNDNS_CONFIG`.

### Deprecated

No deprecated features.

### Removed

- Removed dependency on the external `nsupdate` binary for DNS updates.

### Fixed

- Fixed compile errors after dependency updates by switching password-hash and RNG imports to the `argon2` re-exported paths used by current crate versions.

### Security

No security updates.

---

## [3.0.1] - 2026-03-02

### Added

No new features.

### Changed

- Updated project dependencies to current crate versions.
- Regenerated `Cargo.lock`.

### Deprecated

No deprecated features.

### Removed

No removed features.

### Fixed

No bug fixes.

### Security

- No security-specific changes documented.

## [3.0.0] - 2025-12-20

### Added

- systemd socket activation: reuses a socket passed in by systemd before binding its own `/run/kdyndns/kdyndns.sock`, enabling socket-managed startup and permissions.

### Changed

- Documentation now highlights the systemd socket handling flow to set up matching service/socket units.

### Deprecated

No deprecated features.

### Removed

No removed features.

### Fixed

No bug fixes in this set of staged changes.

### Security

No security updates.

---

## [2.0.0] - 2025-12-20

### Added

- No new features in this release; focus on API rename and stricter validation.

### Changed

- **Breaking:** `/update` query parameters renamed to `ipv4` / `ipv6`; clients must switch from the old IP fields.
- Requests with missing, empty, or invalid `ipv4`/`ipv6` now return `400 Bad Request`; host names are normalized before logging/updating.
- Update logging now includes normalized host and both IP versions; request validation tightened.

### Deprecated

No deprecated features.

### Removed

- Legacy `/update` query parameters (old IP fields) are no longer accepted; requests using them now return `400 Bad Request`.

### Fixed

No bug fixes in this set of staged changes.

### Security

No security updates.

---

## [1.0.0] - 2025-12-14

### Added

- Initial project manifest files: `Cargo.toml`, `Cargo.lock`.
- Build and helper scripts: `build.sh`, `test.sh`.
- Documentation: `README.md`.
- License: `LICENSE`
- Core source files: `src/auth.rs`, `src/config.rs`, `src/dns.rs`, `src/handlers.rs`, `src/main.rs`.
- Support configuration and packaging: `support/config.toml`, `support/nginx/nginx.conf`, `support/systemd/kdyndns.service`.

### Changed

No changes.

### Deprecated

No deprecated features.

### Removed

No removed features.

### Fixed

No bug fixes in this set of staged changes.

### Security

No security updates.

---
