#!/usr/bin/env python
"""Script for deploying homelab"""

import argparse
import copy
import fcntl
import functools
import grp
import json
import logging
import os
import pwd
import socket
import struct
import subprocess
import time
import typing
from collections.abc import Mapping
from dataclasses import dataclass, field, fields, is_dataclass
from ipaddress import (
    AddressValueError,
    IPv4Address,
    IPv4Network,
    IPv6Address,
    IPv6Network,
)
from pathlib import Path
from typing import Any, Callable, Optional, TextIO, TypeVar

import requests


class ColoredFormatter(logging.Formatter):
    MAPPING: Mapping[str, int] = {
        "DEBUG": 37,  # white
        "INFO": 36,  # cyan
        "WARNING": 33,  # yellow
        "ERROR": 31,  # red
        "CRITICAL": 41,  # white on red bg
    }
    PREFIX = "\033["
    SUFFIX = "\033[0m"

    def __init__(self, patern):
        super().__init__(patern)

    def format(self, record):
        colored_record = copy.copy(record)
        levelname = colored_record.levelname
        seq = self.MAPPING.get(levelname, 37)  # default white
        colored_levelname = f"{self.PREFIX}{seq}m{levelname}{self.SUFFIX}"
        colored_record.levelname = colored_levelname
        return super().format(colored_record)


logger = logging.getLogger("Deployer")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setLevel(logging.INFO)
formatter = ColoredFormatter("[%(levelname)s] --- %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)

_DOCKER_JSON_ENV_VARIABLE = "RPI_DOCKER_JSON_DIR"
_RUST_TARGET_ENV_VARIABLE = "RPI_DOCKER_RUST_TARGET"
_MAIN_VIDEO_DEVICE = "RPI_DOCKER_VIDEO_DEVICE"

TJSONDataclass = TypeVar("TJSONDataclass", bound="JSONDataclass")


class JSONDataclass:
    @classmethod
    def from_json(cls: type[TJSONDataclass], fp: TextIO) -> TJSONDataclass:
        dct = json.load(fp)
        return cls.from_dict(dct)

    @classmethod
    def from_json_s(cls: type[TJSONDataclass], s: str) -> TJSONDataclass:
        dct = json.loads(s)
        return cls.from_dict(dct)

    @classmethod
    def from_dict(cls: type[TJSONDataclass], dct: dict[str, Any]) -> TJSONDataclass:
        assert is_dataclass(cls)

        field_types = {field.name: field.type for field in fields(cls)}
        for field_name, field_type in field_types.items():
            # TODO: fix for field types that are typing.List, Unions etc
            if isinstance(field_type, type) and issubclass(field_type, JSONDataclass) and field_name in dct:
                assert is_dataclass(field_type)
                dct[field_name] = field_type.from_dict(dct[field_name])  # type: ignore[unknown]

        return cls(**dct)


@dataclass
class LocalPaths(JSONDataclass):
    data_dir: str
    backup_dir: str


@dataclass
class OwncloudConfig(JSONDataclass):
    docker_image: str = "owncloud/ocis-rolling"
    docker_tag: str = "latest"
    password: str = "admin"
    domain: Optional[str] = None
    smtp_host: str = ""
    smtp_port: str = ""
    smtp_sender: str = ""
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_authentication: str = ""
    smtp_insecure: bool = False


@dataclass
class CloudflareConfig(JSONDataclass):
    email: str
    api_key: str
    domain: str
    include_owncloud_subdomain: bool = True
    subdomains: list[str] = field(default_factory=list)

    def __post_init__(self):
        # Remove duplicates
        self.subdomains = list(set(self.subdomains))


@dataclass
class TraefikConfig(JSONDataclass):
    le_email: str  # Email for Let's encrypt


@dataclass
class DuplicityConfig(JSONDataclass):
    password: str  # Password used to encrypt backups
    offsite_dest: str
    access_key: str
    secret_key: str


@dataclass
class PiHoleConfig(JSONDataclass):
    password: str
    upstream_dns: list[str] = field(default_factory=lambda: ["8.8.8.8", "8.8.4.4"])
    use_gateway_as_dns: bool = True

    def __post_init__(self):
        seen = set()
        deduplicated = []
        # Maintain order
        for dns in self.upstream_dns:
            if dns not in seen:
                seen.add(dns)
                deduplicated.append(dns)
        self.upstream_dns = deduplicated


@dataclass
class JellyfinConfig(JSONDataclass):
    webdav_url: str
    webdav_user: str
    webdav_pass: str
    webdav_bearer_token_command: str
    host_video_gid: Optional[int] = None

    def __post_init__(self):
        if self.host_video_gid is None:
            if video_dev := os.environ.get(_MAIN_VIDEO_DEVICE) is None:
                video_dev = "/dev/video10"

            try:
                stat_info = os.stat(video_dev)
                gid = stat_info.st_gid
                logger.info(f"Video GID is not set..automatically setting it to {gid}...")
                self.host_video_gid = gid
            except Exception as e:
                raise RuntimeError("Could not detect video GID...Use the host_video_gid argument...") from e


@dataclass
class NetworkConfig(JSONDataclass):
    iface_name: Optional[str] = None
    ipv4_gateway: Optional[str] = None
    ipv4_subnet: Optional[str] = None
    ipv4_host: Optional[str] = None
    ipv6_host: Optional[str] = None
    ipv6_gateway: Optional[str] = None

    def __post_init__(self):
        def check_ipv4_address(addr: str):
            _ = IPv4Address(addr)
            return True

        def check_ipv4_network(cidr_notation: str):
            _ = IPv4Network(cidr_notation, strict=True)
            return True

        def check_ipv6_address(addr: str):
            _ = IPv6Address(addr)
            return True

        if self.ipv4_gateway:
            check_ipv4_address(self.ipv4_gateway)
        if self.ipv4_subnet:
            check_ipv4_network(self.ipv4_subnet)
        if self.ipv4_host:
            check_ipv4_address(self.ipv4_host)
        if self.ipv6_host:
            check_ipv6_address(self.ipv6_host)
        if self.ipv6_gateway:
            check_ipv6_address(self.ipv6_gateway)


def hex_to_ip_address(hex_str: str) -> IPv4Address | IPv6Address:
    assert len(hex_str) == 8 or len(hex_str) == 32

    if len(hex_str) == 8:
        return IPv4Address(socket.inet_ntoa(struct.pack("<L", int(hex_str, 16))))
    else:
        return IPv6Address(socket.inet_ntop(socket.AF_INET6, int(hex_str, 16).to_bytes(16, "big")))


def hex_to_ipv4_address(hex_str: str) -> IPv4Address:
    res = hex_to_ip_address(hex_str)
    assert isinstance(res, IPv4Address)
    return res


def hex_to_ipv6_address(hex_str: str) -> IPv6Address:
    res = hex_to_ip_address(hex_str)
    assert isinstance(res, IPv6Address)
    return res


def get_ipv4_gateway(
    iface: Optional[str] = None, gateway: Optional[IPv4Address | str] = None
) -> tuple[str, IPv4Address]:
    """
    Read the default gateway directly from /proc/net/route. If either iface or gateway
    is provided, the other one will be autocompleted. If both are provided, the function
    will check if they match
    """

    @dataclass
    class REntry:
        iface: str
        dest: str
        gateway: str
        flags: str
        refcnt: str
        use: str
        metric: str
        mask: str
        mtu: str
        window: str
        irtt: str

    if gateway is not None:
        gateway = IPv4Address(gateway)

    RTF_GATEWAY_MASK = 0x2  # noqa: N806

    entries = []

    route_file = Path("/proc/net/route")
    if not route_file.exists():
        raise RuntimeError("Could not find /proc/net/route...")

    with route_file.open("r") as fh:
        for line in fh:
            entry = REntry(*line.strip().split())
            if entry.dest != "00000000" or not int(entry.flags, 16) & RTF_GATEWAY_MASK:
                # If not default route or not RTF_GATEWAY, skip it
                continue
            try:
                entry_gateway = hex_to_ipv4_address(entry.gateway)
            except Exception:
                continue

            if iface and entry.iface != iface:
                continue

            if gateway and entry_gateway != gateway:
                continue

            entries.append(entry)

    if not entries:
        raise RuntimeError("Could not find any relevant entries in /proc/net/route")

    entry = min(entries, key=lambda x: int(x.metric))
    return entry.iface, hex_to_ipv4_address(entry.gateway)


def get_ipv6_address(iface: str) -> IPv6Address:
    inet6_path = Path("/proc/net/if_inet6")
    if not inet6_path.exists():
        raise RuntimeError("Could not find /proc/net/if_inet6...")

    with inet6_path.open("r") as fh:
        for line in fh:
            fields = line.strip().split()
            if fields[-1] != iface:
                continue

            try:
                ipv6 = hex_to_ip_address(fields[0])
                assert isinstance(ipv6, IPv6Address)
            except Exception:
                continue

            if ipv6 not in IPv6Network("fd00::/8"):
                continue

            return ipv6

    raise RuntimeError(f"Could not find IPv6 address for interface {iface}")


def get_ipv6_gateway(
    iface: Optional[str] = None, gateway: Optional[IPv6Address | str] = None
) -> tuple[str, IPv6Address]:
    """
    Read the default gateway directly from /proc/net/ipv6_route. If either iface or gateway
    is provided, the other one will be autocompleted. If both are provided, the function
    will check if they match
    """

    @dataclass
    class REntry:
        dest: str
        dest_prefix: str
        src: str
        src_prefix: str
        next_hop: str
        metric: str
        refcnt: str
        usecnt: str
        flags: str
        iface: str

    if gateway is not None:
        gateway = IPv6Address(gateway)

    RTF_GATEWAY_MASK = 0x2  # noqa: N806

    entries: list[REntry] = []

    route_file = Path("/proc/net/ipv6_route")
    if not route_file.exists():
        raise RuntimeError("Could not find /proc/net/ipv6_route...")

    with route_file.open("r") as fh:
        for line in fh:
            entry = REntry(*line.strip().split())
            if entry.dest != "00000000000000000000000000000000" or not int(entry.flags, 16) & RTF_GATEWAY_MASK:
                # If not default route or not RTF_GATEWAY, skip it
                continue
            try:
                entry_hop = hex_to_ipv6_address(entry.next_hop)
            except Exception:
                continue

            if iface and entry.iface != iface:
                continue

            if gateway and entry_hop != gateway:
                continue

            entries.append(entry)

    if not entries:
        raise RuntimeError("Could not find any relevant entries in /proc/net/ipv6_route")

    entry = min(entries, key=lambda x: int(x.metric))
    return entry.iface, hex_to_ipv6_address(entry.next_hop)


def complete_network_config(nconfig: NetworkConfig) -> NetworkConfig:
    iface = nconfig.iface_name
    ipv4_host = IPv4Address(nconfig.ipv4_host) if nconfig.ipv4_host is not None else None
    ipv4_gateway = IPv4Address(nconfig.ipv4_gateway) if nconfig.ipv4_gateway is not None else None
    ipv4_subnet = IPv4Network(nconfig.ipv4_subnet) if nconfig.ipv4_subnet is not None else None
    ipv6_host = IPv6Address(nconfig.ipv6_host) if nconfig.ipv6_host is not None else None
    ipv6_gateway = IPv6Address(nconfig.ipv6_gateway) if nconfig.ipv6_gateway is not None else None

    # Find iface and gateways
    if iface is None or ipv4_gateway is None:
        iface, ipv4_gateway = get_ipv4_gateway(iface, ipv4_gateway)

    if len(iface) > 15:
        raise ValueError("Interface name should not be longer than 15 characters")

    if ipv6_gateway is None:
        _, ipv6_gateway = get_ipv6_gateway(iface, ipv6_gateway)

    # Find IPv4 addresses
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ifname_packed = struct.pack("256s", bytes(iface, "utf-8"))

    SIOCGIFADDR = 0x8915  # get IPv4 address  # noqa: N806
    SIOCGIFNETMASK = 0x891B  # get subnet mask  # noqa: N806

    if ipv4_host is None:
        out_struct = fcntl.ioctl(s.fileno(), SIOCGIFADDR, ifname_packed)
        ipv4_host = IPv4Address(socket.inet_ntoa(out_struct[20:24]))

    if ipv4_subnet is None:
        out_struct = fcntl.ioctl(s.fileno(), SIOCGIFNETMASK, ifname_packed)
        ipv4_subnet_mask = socket.inet_ntoa(out_struct[20:24])
        # strict=False since we do not want it complain about host bits being set
        ipv4_subnet = IPv4Network(f"{ipv4_host}/{ipv4_subnet_mask}", strict=False)

    if ipv4_gateway not in ipv4_subnet:
        raise ValueError(f"Gateway {ipv4_gateway} is not in {ipv4_subnet}")

    if ipv4_host not in ipv4_subnet:
        raise ValueError(f"Host {ipv4_host} is not in {ipv4_subnet}")

    # Find IPv6 addresses
    if ipv6_host is None:
        ipv6_host = get_ipv6_address(iface)

    if ipv6_host not in IPv6Network("fd00::/8"):
        raise ValueError(
            f"IPv6 {ipv6_host} not in the range of ULA addresses. Make sure to enable assigning of ULA "
            "addresses in your router's settings"
        )

    new_nconfig = NetworkConfig(
        iface_name=iface,
        ipv4_gateway=ipv4_gateway.compressed,
        ipv4_subnet=ipv4_subnet.compressed,
        ipv4_host=ipv4_host.compressed,
        ipv6_host=ipv6_host.exploded,
        ipv6_gateway=ipv6_gateway.exploded,
    )

    return new_nconfig


@dataclass
class Config(JSONDataclass):
    paths: LocalPaths
    owncloud: OwncloudConfig
    cloudflare: CloudflareConfig
    traefik: TraefikConfig
    duplicity: DuplicityConfig
    pihole: PiHoleConfig
    jellyfin: JellyfinConfig
    network: NetworkConfig = field(default_factory=NetworkConfig)

    def __post_init__(self):
        logger.info("Detecting network settings...")
        self.network = complete_network_config(self.network)

        if self.cloudflare.include_owncloud_subdomain and self.owncloud.domain:
            domain = self.owncloud.domain
            # Filter ports if any
            domain = domain.split(":")[0]
            if domain.endswith(self.cloudflare.domain):
                domain = domain.split(f".{self.cloudflare.domain}")[0]
            self.cloudflare.subdomains.append(domain)
            self.cloudflare.subdomains = list(set(self.cloudflare.subdomains))

        if self.pihole.use_gateway_as_dns:
            for gateway in [self.network.ipv6_gateway, self.network.ipv4_gateway]:
                assert gateway is not None, "Something wrong happened"
                self.pihole.upstream_dns = [gateway, *self.pihole.upstream_dns]


@typing.no_type_check
def run_as_root(func: Callable) -> Callable:
    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        current_euid = os.geteuid()
        current_egid = os.getegid()
        current_groups = os.getgroups()

        root_info = pwd.getpwuid(0)
        root_groups = [g.gr_gid for g in grp.getgrall() if root_info.pw_name in g.gr_mem]
        os.seteuid(0)
        os.setegid(0)
        os.setgroups(root_groups)

        retval = func(*args, **kwargs)
        os.setgroups(current_groups)
        os.setegid(current_egid)
        os.seteuid(current_euid)
        return retval

    return wrapper


def get_docker_config_path() -> Path:
    docker_json_path: Path | str | None
    if (docker_json_path := os.environ.get(_DOCKER_JSON_ENV_VARIABLE)) is None:
        docker_json_path = "/etc/docker/daemon.json"

    return Path(docker_json_path)


def check_docker_ipv6() -> bool:
    docker_json_path = get_docker_config_path()

    if not docker_json_path.exists():
        logger.warning("No docker daemon.json file was found in %s.", docker_json_path)
        return False

    docker_config: dict[str, Any] = json.loads(docker_json_path.read_text())
    if docker_config.get("ipv6") is not True:
        logger.warning("The flag `ipv6` is not set to true in docker daemon.json")
        return False
    if docker_config.get("experimental") is not True:
        logger.warning("The flag `experimental` is not set to true in docker daemon.json")
        return False
    if docker_config.get("ip6tables") is not True:
        logger.warning("The flag `ip6tables` is not set to true in docker daemon.json")
        return False
    if docker_config.get("fixed-cidr-v6") is None:
        logger.warning("The setting `fixed-cidr-v6` could not be found or is set to null")
        return False

    try:
        ipv6_address = IPv6Network(docker_config.get("fixed-cidr-v6"), strict=True)
    except AddressValueError:
        logger.warning("Invalid IPv6 format in daemon.json file")
        return False

    if not ipv6_address.subnet_of(IPv6Network("fd00::/8")):
        logger.warning("Docker IPv6 address is not a subnet of fd00::/8 which is the range for ULA addresses")
        return False

    return True


def get_docker_ipv6_network() -> IPv6Network:
    """Retrieves an IPv6Network object from the daemon.json file. This function assumes the file exists"""
    docker_json_path = get_docker_config_path()

    docker_config: dict[str, Any] = json.loads(docker_json_path.read_text())

    return IPv6Network(docker_config["fixed-cidr-v6"], strict=True)


@run_as_root
def correct_docker_config(ipv6_network: Optional[IPv6Network] = None):
    docker_json_path = get_docker_config_path()

    try:
        docker_config: dict[str, Any] = json.loads(docker_json_path.read_text())
    except Exception:
        docker_json_path.parent.mkdir(exist_ok=True, parents=True)
        docker_config = {}

    docker_config["ipv6"] = True
    docker_config["experimental"] = True
    docker_config["ip6tables"] = True

    if not ipv6_network:
        ipv6_network = IPv6Network("fd00:dead:beef:0000::/64", strict=True)

    docker_config["fixed-cidr-v6"] = ipv6_network.compressed

    docker_json_path.write_text(json.dumps(docker_config))


def get_rust_target() -> str:
    if (target := os.environ.get(_RUST_TARGET_ENV_VARIABLE)) is not None:
        return target

    try:
        process = subprocess.run(["rustup", "default"], check=True, text=True, capture_output=True)
        target = process.stdout.strip().split(" ")[0].split("-", 1)[1]
        return target
    except Exception:
        if os.getuid() == 0 and (username := os.environ.get("SUDO_USER")) is not None:
            rustup_settings = (Path("/home") / username / ".rustup" / "settings.toml").read_text().split("\n")
            for line in rustup_settings:
                if line.startswith("default_toolchain"):
                    target = line.split("=")[1].strip('"').split("-", 1)[1]
                    return target
        raise


def compile_rust_code(project_root: str | Path) -> None:
    project_root = Path(project_root).absolute()

    target = get_rust_target()
    arch = target.split("-")[0]
    docker_tag = f"{arch}-musl"

    cmd = [
        "docker",
        "run",
        "--rm",
        "-it",
        "-v",
        f"{project_root!s}:/home/rust/src",
        "-v",
        "cargo-git:/root/.cargo/git",
        "-v",
        "cargo-registry:/root/.cargo/registry",
        f"messense/rust-musl-cross:{docker_tag}",
        "cargo",
        "install",
        "--locked",
        "--path",
        "/home/rust/src",
        "--root",
        "/home/rust/src/build",
    ]
    subprocess.run(cmd, check=True)


def generate_dotenv(config: Config):
    env = {}
    env["DATA_PATH"] = str(config.paths.data_dir)
    env["LOCAL_BACKUP_PATH"] = str(config.paths.backup_dir)

    env["OCIS_DOCKER_IMAGE"] = str(config.owncloud.docker_image)
    env["OCIS_DOCKET_TAG"] = str(config.owncloud.docker_tag)
    env["ADMIN_PASSWORD"] = str(config.owncloud.password)
    env["OCIS_DOMAIN"] = str(config.owncloud.domain)
    env["SMTP_HOST"] = str(config.owncloud.smtp_host)
    env["SMTP_PORT"] = str(config.owncloud.smtp_port)
    env["SMTP_SENDER"] = str(config.owncloud.smtp_sender)
    env["SMTP_USERNAME"] = str(config.owncloud.smtp_username)
    env["SMTP_PASSWORD"] = str(config.owncloud.smtp_password)
    env["SMTP_AUTHENTICATION"] = str(config.owncloud.smtp_authentication)
    env["SMTP_INSECURE"] = str(config.owncloud.smtp_insecure)

    assert len(config.cloudflare.subdomains) >= 1, "Currently at least one subdomain is required"
    env["CLOUDFLARE_EMAIL"] = str(config.cloudflare.email)
    env["CLOUDFLARE_KEY"] = str(config.cloudflare.api_key)
    env["CLOUDFLARE_DOMAIN"] = str(config.cloudflare.domain)
    env["CLOUDFLARE_SUBDOMAINS"] = ",".join(config.cloudflare.subdomains)

    env["TRAEFIK_EMAIL"] = str(config.traefik.le_email)

    env["DUPLICITY_PASSWORD"] = str(config.duplicity.password)
    env["DUPLICITY_OFFSITE_DEST"] = str(config.duplicity.offsite_dest)
    env["AWS_ACCESS_KEY"] = str(config.duplicity.access_key)
    env["AWS_SECRET_KEY"] = str(config.duplicity.secret_key)

    env["PIHOLE_PASSWORD"] = str(config.pihole.password)
    env["PIHOLE_UPSTREAM_DNS"] = ";".join(config.pihole.upstream_dns)
    env["LOCAL_IPV4_GATEWAY"] = str(config.network.ipv4_gateway)
    env["LOCAL_IPV4_SUBNET"] = str(config.network.ipv4_subnet)
    env["LOCAL_IPV4"] = str(config.network.ipv4_host)
    env["LOCAL_IPV6"] = str(config.network.ipv6_host)

    env["WEBDAV_URL"] = f"'{config.jellyfin.webdav_url!s}'"
    env["WEBDAV_USER"] = str(config.jellyfin.webdav_user)
    env["WEBDAV_BEARER_TOKEN_COMMAND"] = str(config.jellyfin.webdav_bearer_token_command)
    env["HOST_VIDEO_GID"] = str(config.jellyfin.host_video_gid)

    cmd = ["./general/dotenv_writer/build/bin/dotenv_writer"]
    for key, val in env.items():
        cmd.extend(["-D", f"{key}={val}"])
    cmd.extend(["--output", "./"])
    subprocess.run(cmd, check=True)


def generate_pihole_config(config: Config):
    assert config.network.ipv4_host is not None, "IPv4 host address cannot be None"
    assert config.network.ipv4_gateway is not None, "IPv4 gateway cannot be None"

    # Configure IPv6 hostname resolving
    dest_directory = Path("./pihole/etc-dnsmasq.d/")
    dest_directory.mkdir(parents=True, exist_ok=True)
    src_text = Path("./pihole/99-forwarders.conf").read_text()
    final_text = src_text.replace("<ipv4-gateway>", config.network.ipv4_gateway)
    (dest_directory / "99-forwarders.conf").write_text(final_text)

    # Configure custom DNS entries
    custom_dns = []
    existing_dns_entries_file = Path("./pihole/etc-pihole/custom.list")
    if existing_dns_entries_file.exists():
        existing_dns_text = existing_dns_entries_file.read_text().strip().split("\n")
        custom_dns.extend([tuple(entry.split(" ", 1)) for entry in existing_dns_text])
    custom_dns.extend(
        [
            (config.network.ipv4_host, "rpi.home"),
            (config.network.ipv4_host, "owncloud.home"),
            (config.network.ipv4_host, "pihole.home"),
            (config.network.ipv4_host, "jellyfin.home"),
            (config.network.ipv4_host, "glances.home"),
            (config.network.ipv4_host, "welcome.home"),
            (config.network.ipv4_gateway, "router.home"),
        ]
    )
    custom_dns = list(set(custom_dns))
    custom_dns_text = "\n".join([" ".join(entry) for entry in custom_dns])
    existing_dns_entries_file.parent.mkdir(exist_ok=True, parents=True)
    existing_dns_entries_file.write_text(custom_dns_text)


def check_and_fix_acme_json():
    acme_file = Path("./traefik/acme.json")
    if not acme_file.exists():
        logger.warning("acme.json does not exist...creating...")
        acme_file.touch()

    if oct(acme_file.stat().st_mode) != "0o100600":
        logger.warning("Fixing acme.json permissions...")
        acme_file.chmod(0o600)


def get_interactive_authorization(owncloud_domain: str) -> str:
    authorization_url = f"https://{owncloud_domain}/signin/v1/identifier/_/authorize?client_id=xdXOt13JKxym1B1QcEncf2XDkLAexMBFwiT9j6EfhhHFJhs2KM9jbjTmf8JBXE69&scope=openid+profile+email+offline_access&response_type=code&redirect_uri=http://localhost"
    logger.info(
        f"Use the following URL to retrieve an authorization code for the admin user:\n\n{authorization_url}\n\n"
    )

    code = input("Enter the authorization code here: ")
    return code


def refresh_access_token(owncloud_domain: str, refresh_token: str) -> str:
    url = f"https://{owncloud_domain}/konnect/v1/token"
    r = requests.post(
        url=url,
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token.strip(),
            "redirect_uri": "http://localhost",
            "client_id": "xdXOt13JKxym1B1QcEncf2XDkLAexMBFwiT9j6EfhhHFJhs2KM9jbjTmf8JBXE69",
            "client_secret": "UBntmLjC2yYCeHwsyj73Uwo9TAaecAetRwMw0xYcvNL9yRdLSUi0hUAHfvCHFeFh",
        },
    )
    r.raise_for_status()
    result = r.json()
    return str(result["access_token"])


def get_access_and_refresh_token(owncloud_domain: str, auth_code: str) -> tuple[str, str]:
    url = f"https://{owncloud_domain}/konnect/v1/token"
    r = requests.post(
        url=url,
        data={
            "grant_type": "authorization_code",
            "code": auth_code.strip(),
            "redirect_uri": "http://localhost",
            "client_id": "xdXOt13JKxym1B1QcEncf2XDkLAexMBFwiT9j6EfhhHFJhs2KM9jbjTmf8JBXE69",
            "client_secret": "UBntmLjC2yYCeHwsyj73Uwo9TAaecAetRwMw0xYcvNL9yRdLSUi0hUAHfvCHFeFh",
        },
    )
    r.raise_for_status()
    result = r.json()
    return result["access_token"], result["refresh_token"]


def get_access_token(owncloud_domain: str) -> str:
    refresh_token_file = Path(__file__).parent / ".refresh_token"
    retry = True
    access_token = None
    while retry:
        if refresh_token_file.exists():
            refresh_token = refresh_token_file.read_text()
            try:
                access_token = refresh_access_token(owncloud_domain, refresh_token)
            except Exception as _:
                logger.warn("Cannot refresh access token...falling back to interactive authorization...")
                refresh_token_file.unlink(missing_ok=True)
        else:
            code = get_interactive_authorization(owncloud_domain)
            access_token, refresh_token = get_access_and_refresh_token(owncloud_domain, code)
            refresh_token_file.write_text(refresh_token)

        if access_token is not None:
            retry = False

    assert access_token is not None
    return access_token


def check_owncloud_user_exists(user: str, owncloud_domain: str, access_key: str) -> bool:
    url = f"https://{owncloud_domain}/graph/v1.0/users"
    r = requests.get(url, headers={"Authorization": f"Bearer {access_key.strip()}"})
    r.raise_for_status()

    users = r.json()["value"]
    return any(entry["accountEnabled"] is True and entry["onPremisesSamAccountName"] == user for entry in users)


def add_owncloud_user(user: str, password: str, owncloud_domain: str, access_key: str):
    url = f"https://{owncloud_domain}/graph/v1.0/users"
    data = {
        "displayName": "Movie User",
        "mail": "",
        "onPremisesSamAccountName": user,
        "passwordProfile": {"password": password},
    }
    r = requests.post(url, json=data, headers={"Authorization": f"Bearer {access_key.strip()}"})
    r.raise_for_status()


def check_rclone_plugin() -> bool:
    plugin_out = subprocess.run(
        [
            "docker",
            "plugin",
            "list",
            "--format",
            "{{.Name}},{{.Enabled}}",
        ],
        check=True,
        text=True,
        capture_output=True,
    ).stdout.strip()
    for line in plugin_out.split("\n"):
        plugin, enabled = line.split(",")
        if plugin.startswith("rclone") and enabled == "true":
            return True
    return False


@run_as_root
def install_rclone_plugin():
    config_path = Path("/var/lib/docker-plugins/rclone_oidc/config")
    config_path.mkdir(exist_ok=True, parents=True)
    cache_path = Path("/var/lib/docker-plugins/rclone_oidc/cache")
    cache_path.mkdir(exist_ok=True, parents=True)

    proc = subprocess.run(["oidc-agent", "--json"], text=True, check=True, capture_output=True)
    oidc_agent_data = json.loads(proc.stdout)
    oidc_socket = oidc_agent_data["socket"]
    oidc_socket_symlink = Path("/var/lib/docker-plugins/rclone_oidc/oidc_socket")
    oidc_socket_symlink.unlink(missing_ok=True)
    oidc_socket_symlink.symlink_to(oidc_socket)

    oidc_agent_config = Path.home() / ".config" / "oidc-agent"
    oidc_agent_config_symlink = Path("/var/lib/docker-plugins/rclone_oidc/oidc_config")
    oidc_agent_config_symlink.unlink(missing_ok=True)
    oidc_agent_config_symlink.symlink_to(oidc_agent_config, target_is_directory=True)

    install_script = Path(__file__).parent / "rclone_plugin" / "install_plugin.sh"

    subprocess.check_call([f"./{install_script.name}"], cwd=install_script.parent)
    subprocess.run(["docker", "plugin", "enable", "rclone_oidc"], check=True)


def main():
    parser = argparse.ArgumentParser(description="Tool for deploying homelab")
    parser.add_argument(
        "--fix-docker-config",
        action="store_true",
        help="Correct docker daemon.json file if an error is found (requires root)",
    )
    parser.add_argument(
        "--install-rclone-plugin",
        action="store_true",
        help="Install the docker rclone plugin if not found (requires root)",
    )
    parser.add_argument("-y", action="store_true", help="Do not prompt user for confirmation")
    args = parser.parse_args()

    requires_root = False

    if args.fix_docker_config or args.install_rclone_plugin:
        requires_root = True

    if requires_root:
        if os.getuid() != 0:
            logger.error("You cannot perform this operation unless you are root. Please rerun with sudo")
            return
        if os.getenv("SUDO_UID") is None:
            logger.error("Could not find env variable SUDO_UID. Are you sure you are running with sudo?")
            return
        user_info = pwd.getpwuid(int(os.environ["SUDO_UID"]))
        user_groups = [g.gr_gid for g in grp.getgrall() if user_info.pw_name in g.gr_mem]
        os.setgroups(user_groups)
        os.setegid(int(os.environ["SUDO_GID"]))
        os.seteuid(int(os.environ["SUDO_UID"]))

    if (arch := os.uname().machine) != "aarch64":
        logger.warning(
            "This deployment script was made for RPi 4B which is aarch64..Current architecture is %s. "
            "The script might fail on other architectures...",
            arch,
        )
        time.sleep(2)

    config_path = Path(__file__).resolve().absolute().parent / "config.json"
    logger.info("Reading config...")
    try:
        config = Config.from_json_s(config_path.read_text())
    except Exception as e:
        logger.error(str(e))
        return

    logger.info("Detected interface name: %s", config.network.iface_name)
    logger.info("Detected gateway IPv4 address: %s", config.network.ipv4_gateway)
    logger.info("Detected IPv4 subnet: %s", config.network.ipv4_subnet)
    logger.info("Detected host IPv4 address: %s", config.network.ipv4_host)
    logger.info("Detected host IPv6 address: %s", config.network.ipv6_host)
    logger.info("Detected gateway IPv6 address: %s", config.network.ipv6_gateway)

    if not args.y:
        print()
        input("If the detected settings are correct, press *any key* to continue...Otherwise press Ctrl+C to terminate")

    logger.info("Checking docker config daemon.json...")
    if not check_docker_ipv6():
        if not args.fix_docker_config:
            logger.error(
                "Your docker daemon.json file appears to be misconfigured. Re-run with --fix-docker-config if you would like to fix it."
            )
            return

        logger.info("Fixing daemon.json...")
        correct_docker_config()

    logger.info("Checking if docker plugin rclone is properly configured...")
    if not check_rclone_plugin():
        if not args.install_rclone_plugin:
            logger.error(
                "The docker plugin rclone appears to be misconfigured or it is not installed. "
                "Re-run with --install-rclone-plugin if you would like to fix it."
            )
            return
        logger.info("Fixing docker rclone plugin...")
        install_rclone_plugin()

    logger.info("Compiling dotenv-writer...")
    compile_rust_code("./general/dotenv_writer")

    logger.info("Compiling cf_dyndns...")
    compile_rust_code("./cron/cloudflare-dns")

    logger.info("Generating PiHole configuration files from templates")
    generate_pihole_config(config)

    logger.info("Checking acme.json permissions...")
    check_and_fix_acme_json()

    logger.info("Generating .env file...")
    generate_dotenv(config)

    logger.info("Starting docker containers...(Stage 1)")
    subprocess.run(["docker-compose", "up", "-d", "ocis"], check=True)
    time.sleep(5)

    logger.info("Checking if WebDAV jellyfin user exists in OwnCloud...")
    assert config.owncloud.domain is not None
    access_token = get_access_token(config.owncloud.domain)
    if not check_owncloud_user_exists(
        config.jellyfin.webdav_user, owncloud_domain=config.owncloud.domain, access_key=access_token
    ):
        logger.warning("No OwnCloud user %s was found...creating...", config.jellyfin.webdav_user)
        add_owncloud_user(
            config.jellyfin.webdav_user, config.jellyfin.webdav_pass, config.owncloud.domain, access_token
        )

    logger.info("Starting docker containers...(Stage 2)")
    subprocess.run(["docker-compose", "up", "-d"], check=True)


if __name__ == "__main__":
    main()
