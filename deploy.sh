#!/usr/bin/env bash
set -ex

export $(grep LOCAL_IPV4_GATEWAY= .env | xargs)
mkdir -p ./pihole/etc-dnsmasq.d/
cp ./pihole/99-forwarders.conf ./pihole/etc-dnsmasq.d/.

sed -i "s|<ipv4-gateway>|$LOCAL_IPV4_GATEWAY|g" ./pihole/etc-dnsmasq.d/99-forwarders.conf

docker-compose up -d &
