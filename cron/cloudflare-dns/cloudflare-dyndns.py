#!/usr/bin/env python3
"""
#####################################
#      Cloudflare DynDNS Tool       #
#===================================#
# This tool automatically updates   #
# the DNS A record for a subdomain  #
# in a Cloudflare account to the    #
# current IP address of the         #
# computer. Run this on your home   #
# network on a schedule and your    #
# home DNS entry will always be     #
# up to date.                       #
#####################################
"""

import argparse
import logging
import subprocess
from dataclasses import dataclass
from pathlib import Path
from sre_constants import SUCCESS

import requests
from dotenv import dotenv_values

logging.basicConfig(
    format="%(asctime)s %(levelname)-8s %(message)s",
    level=logging.INFO,
    datefmt="%Y-%m-%d %H:%M:%S",
)
logging.getLogger().setLevel(logging.INFO)


@dataclass(frozen=True)
class DNSRecord:
    dns_id: str
    ip: str


def get_ip() -> str:
    return subprocess.run(
        ["curl", "-4", "-s", "-X", "GET", "https://icanhazip.com"],
        capture_output=True,
        check=True,
        text=True,
    ).stdout.strip()


def get_cloudflare_zone_id(domain: str, email: str, api_key: str) -> str:
    url = f"https://api.cloudflare.com/client/v4/zones?name={domain}&status=active&page=1&per_page=20&order=status&direction=desc&match=all"
    headers = {
        "X-Auth-Email": email,
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    return requests.get(url, headers=headers).json()["result"][0]["id"]


def get_dns_record(
    full_domain: str, zone_id: str, email: str, api_key: str
) -> DNSRecord:
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?type=A&name={full_domain}&page=1&per_page=20&order=type&direction=desc&match=all"
    headers = {
        "X-Auth-Email": email,
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    res = requests.get(url, headers=headers).json()
    return DNSRecord(dns_id=res["result"][0]["id"], ip=res["result"][0]["content"])


def update_dns_record(
    full_domain: str, zone_id: str, email: str, api_key: str, record: DNSRecord
) -> bool:
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record.dns_id}"
    headers = {
        "X-Auth-Email": email,
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    data = {"type": "A", "name": full_domain, "content": record.ip}
    res = requests.put(url, headers=headers, json=data).json()
    return res["success"]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sync IP with Cloudflare DNS")
    parser.add_argument(
        "--dotenv-dir", type=Path, help="Path to dir containing a dotenv file"
    )
    args = parser.parse_args()

    config = dotenv_values(str(args.dotenv_dir / ".env"))

    DOMAIN = config["CLOUDFLARE_DOMAIN"]  # Domain name for your account
    SUBDOMAIN_LIST = [
        config["CLOUDFLARE_SUBDOMAINS"]
    ]  # Subdomain(s) to update to new IP
    EMAIL = config["CLOUDFLARE_EMAIL"]  # Cloudflare login email
    API_KEY = config["CLOUDFLARE_KEY"]  # Cloudflare API key

    new_ip = get_ip()
    zone_id = get_cloudflare_zone_id(domain=DOMAIN, email=EMAIL, api_key=API_KEY)

    for subdomain in SUBDOMAIN_LIST:
        full_domain = f"{subdomain}.{DOMAIN}"

        old_dns_record = get_dns_record(
            full_domain=full_domain, zone_id=zone_id, email=EMAIL, api_key=API_KEY
        )

        if new_ip != old_dns_record.ip:
            logging.info("Updating IP from %s to %s", old_dns_record.ip, new_ip)

            success = update_dns_record(
                full_domain=full_domain,
                zone_id=zone_id,
                email=EMAIL,
                api_key=API_KEY,
                record=DNSRecord(dns_id=old_dns_record.dns_id, ip=new_ip),
            )

            logging.info("Successfully updated %s: %s", full_domain, str(success))
