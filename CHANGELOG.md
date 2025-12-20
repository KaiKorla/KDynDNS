# Changelog

All notable changes to this project will be documented in this file.

The format is based on <https://keepachangelog.com/en/1.0.0/>

## [Unreleased]

No unreleased changes yet.

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
