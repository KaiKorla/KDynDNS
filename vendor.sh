#!/bin/sh

cargo vendor --locked

mkdir -p .cargo

cat << EOF > .cargo/config.toml
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"
EOF

cargo build --release --locked
cargo clippy --all-targets --all-features -- -D warnings
cargo audit
cargo test --release --locked