# KDynDNS

A minimalistic DynDNS service written in Rust.

## Design & Features

- reverse-proxy operation mode (nginx) via unix-socket
- systemd socket activation support (reuses the provided unix-socket before binding its own)
- simple and plain TOML configuration file (see below)
- HTTP basic auth and Argon2id hashing of the credentials
- IPv4 and IPv6 support including removing of existing entries
- SIGUSR1 support for runtime configuration reloading

## Development

- Rust: <https://rust-lang.org>
  - Dependencies are vendored for offline reproduceable builds.“
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
server = "127.0.0.1"
tsig_key_path = "/etc/bind/keys/dyn.key"
username = "user1"
password_hash = "$argon2id$v=19$m=65536,t=3,p=1$..."
allowed_hosts = ["myhost.example.com."]
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

export KDynDNS=/etc/kdyndns/config.toml
cargo run --release

## Systemd socket activation

When started via systemd with a socket unit, KDynDNS will reuse the pre-opened unix-socket passed in through systemd (LISTEN_FDS). If no socket is provided it falls back to binding `/run/kdyndns/kdyndns.sock` itself. Pair the service with a matching socket unit so systemd manages creation and permissions of the socket.
