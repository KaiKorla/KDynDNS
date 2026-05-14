# KDynDNS

A minimalistic DynDNS service written in Rust.

## Design & Features

- reverse-proxy operation mode (nginx) via unix-socket
- systemd socket activation support (reuses the provided unix-socket before binding its own)
- simple and plain TOML configuration file (see below)
- HTTP basic auth and Argon2id hashing of the credentials
- authentication throttling and bounded password-verification concurrency
- IPv4 and IPv6 DynDNS updates for `A` and `AAAA` only; other RR types stay untouched
- RFC 2136 updates via `hickory-net`/`hickory-proto` (TSIG), no external `nsupdate` binary required
- configuration is validated semantically on startup and `SIGUSR1` reload before it becomes active
- SIGUSR1 support for runtime configuration reloading

## Development

- Rust: <https://rust-lang.org>
  - Dependencies are vendored for offline reproducible builds.
- Conventions:
  - Versioning: <https://semver.org>
  - Changelog: <https://keepachangelog.com>
  - Commits: <https://www.conventionalcommits.org>

## Build

```bash
cargo build --release
```

## Configuration

Edit /etc/kdyndns/config.toml

```toml
[[users]]
server = "udp://127.0.0.1:53"
tsig_key_path = "/etc/bind/keys/dyn.key"
username = "user1"
password_hash = "$argon2id$v=19$m=65536,t=3,p=1$..."
allowed_hosts = ["myhost.example.com."]
```

`server` must point to an authoritative DNS server that accepts RFC 2136 updates for the configured host. KDynDNS discovers the matching zone via SOA before sending the update.

`tsig_key_path` must point to a local TSIG key file readable by the service. Supported TSIG algorithms follow the active Hickory backend and currently are `hmac-sha256`, `hmac-sha384`, and `hmac-sha512`, for example:

```txt
key "dyn-key" {
    algorithm hmac-sha256;
    secret "BASE64_SECRET_HERE";
};
```

Create the password hash:

1. Install argon2 for your operating system
2. Create a random salt

    ```bash
    salt=$(openssl rand -base64 16)
    ```

3. Create the password hash

    ```bash
    echo -n "your-password-here" | argon2 "$salt" -id -t 3 -m 16 -p 1
    ```

    Output:

    ```bash
    Type: Argon2id
    Iterations: 3
    Memory: 65536 KiB
    Parallelism: 1
    Hash: c54955013f9568d732a14587906ee40726527a90cac099f315272a254998960f
    Encoded: $argon2id$v=19$m=65536,t=3,p=1$WnJ1TFZNZEQ0QTR2ZTBJWmU1U3VRZz09$xUlVAT+VaNcyoUWHkG7kByZSepDKwJnzFScqJUmYlg8
    0.209 seconds
    Verification ok
    ```

4. Take the output of the 'Encoded' field and put it into the config.toml

## Run

### From source

```bash
export DYNDNS_CONFIG=/etc/kdyndns/config.toml
cargo run --release
```

## HTTP API

- Transport: HTTP over the unix socket provided by systemd or bound at `/run/kdyndns/kdyndns.sock`; typically fronted by nginx.
- Reverse proxy note: for per-client auth throttling behind nginx, forward the client IP via `X-Forwarded-For` or `X-Real-IP`.
- Authentication: HTTP Basic Auth; users and allowed hosts come from `config.toml`.
- Health check: `GET /health` returns `200 OK` and body `OK` without authentication.
- Update endpoint: `GET /update` with Basic Auth. Query parameters:
  - `host` (required) — trailing dot optional; normalized to a lowercase fully qualified name with trailing dot and must be listed in `allowed_hosts` for the authenticated user.
  - `ipv4` (optional) — IPv4 literal; when present, the host's `A` RRset is replaced with this address.
  - `ipv6` (optional) — IPv6 literal; when present, the host's `AAAA` RRset is replaced with this address.
  - At least one of `ipv4` or `ipv6` must be present and valid.
  - Omitted address families are left unchanged. KDynDNS never modifies RR types other than `A` and `AAAA`.
- Responses: `200 OK` on success; `400` for missing/invalid params; `401` for missing/invalid credentials (with `WWW-Authenticate`); `403` if the host is not allowed; `429` when authentication attempts for the same requester key are throttled; `500` if the DNS update fails.
- Example using curl on the unix socket:

    ```bash
    curl --unix-socket /run/kdyndns/kdyndns.sock \
      -u "user1:your-password" \
      "http://localhost/update?host=myhost.example.com&ipv4=203.0.113.10&ipv6=2001:db8::10"
    ```

## Systemd socket activation

When started via systemd with a socket unit, KDynDNS will reuse the pre-opened unix-socket passed in through systemd (LISTEN_FDS). If no socket is provided it falls back to binding `/run/kdyndns/kdyndns.sock` itself. Pair the service with a matching socket unit so systemd manages creation and permissions of the socket.
