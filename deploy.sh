#!/usr/bin/env bash
set -ex

echo "Installing target aarch64-unknown-linux-musl"
rustup target add aarch64-unknown-linux-musl

echo "Compiling dotenv-writer"
RUSTFLAGS='-C target-feature=+crt-static' cargo build \
    --manifest-path=general/dotenv_writer/Cargo.toml  \
    --release \
    --target=aarch64-unknown-linux-musl

echo "Compiling cf_dyndns"
RUSTFLAGS='-C target-feature=+crt-static' cargo build \
    --manifest-path=cron/cloudflare-dns/Cargo.toml  \
    --release \
    --target=aarch64-unknown-linux-musl

echo "Generating PiHole configuration files from templates"
export $(grep LOCAL_IPV4_GATEWAY= .env | xargs)
mkdir -p ./pihole/etc-dnsmasq.d/
cp ./pihole/99-forwarders.conf ./pihole/etc-dnsmasq.d/.
sed -i "s|<ipv4-gateway>|$LOCAL_IPV4_GATEWAY|g" ./pihole/etc-dnsmasq.d/99-forwarders.conf

docker-compose up -d &