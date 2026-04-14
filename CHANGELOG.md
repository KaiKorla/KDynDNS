# Changelog

All notable changes to this project will be documented in this file.

The format is based on <https://keepachangelog.com/en/1.0.0/>

## [Unreleased]

### Added

No new features.

### Changed

- Updated transitive Rust dependencies in `Cargo.lock` to newer compatible crate versions, including `rand`, `rand_core`, `libc`, `bitflags`, `indexmap`, `hashbrown`, `js-sys`, `wasm-bindgen`, `cc`, `pkg-config`, and `rtoolbox`.
- Regenerated `Cargo.lock` to record the refreshed crate versions, dependency graph metadata, and checksums.

### Deprecated

No deprecated features.

### Removed

No removed features.

### Fixed

No bug fixes.

### Security

No security-specific changes documented.

---

## [4.0.0] - 2026-04-08

### Added

No new features.

### Changed

- **Breaking:** Replaced shell-based DNS updates with a direct `hickory-client` RFC 2136 + TSIG implementation. Per-user `server` values must point to an authoritative RFC 2136 endpoint, and `tsig_key_path` must reference a local readable TSIG key file.
- **Breaking:** DynDNS updates now modify only explicitly requested `A` and `AAAA` RRsets. Omitted address families remain unchanged, and non-address RR types are never touched.
- **Breaking:** Configuration loading now validates password hashes, DNS server URIs, TSIG key files, and allowed hosts before applying startup or reload changes. Invalid configs are rejected earlier than before.
- Internal DNS updater interface is now async; request handling awaits DNS updates directly.
- RFC 2136 updates now discover the authoritative zone via SOA instead of guessing it from the last host labels.
- DNS updates now send requested `A`/`AAAA` changes in a single RFC 2136 update transaction to avoid partial intermediate states.
- Updated examples/docs to match the new DNS server URI style (for example `udp://127.0.0.1:53`) and `DYNDNS_CONFIG`.
- Password verification now runs on bounded blocking workers instead of directly on async request threads.
- The release vendoring workflow now also runs `cargo clippy --all-targets --all-features -- -D warnings` and `cargo audit` alongside release builds and tests.

### Deprecated

No deprecated features.

### Removed

- Removed dependency on the external `nsupdate` binary for DNS updates.

### Fixed

- Fixed compile errors after dependency updates by switching password-hash and RNG imports to the `argon2` re-exported paths used by current crate versions.
- Fixed RFC 2136 updates deleting unrelated RRsets at the same owner name by deleting only `A` and `AAAA`.
- Fixed host normalization and allow-list checks to treat FQDNs case-insensitively.
- Fixed HTTP Basic Auth parsing to accept case-insensitive auth schemes.
- Fixed TSIG algorithm validation to reject algorithms not supported by the active Hickory backend.
- Fixed auth throttling behind reverse proxies by honoring `X-Forwarded-For` / `X-Real-IP` before falling back to the local peer address.
- Fixed username enumeration via auth timing differences by verifying unknown users against a dummy Argon2 hash.
- Fixed config read locks being held across awaited DNS updates.

### Security

- Added in-memory authentication throttling and bounded verification concurrency to reduce brute-force and CPU exhaustion risk.
- Authentication throttling is now scoped per requester key instead of allowing one noisy client to trigger a service-wide lockout.
- Added explicit DNS operation timeouts so slow or hanging upstream DNS servers do not stall update requests indefinitely.
- Sanitized attacker-controlled values before writing them to logs.
- `cargo audit` passes after removing the transitive `rustls-pemfile` warning from the active dependency path.

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
