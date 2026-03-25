"""Server configuration loading and Jinja2 template rendering."""

from __future__ import annotations

import ipaddress
import re
import subprocess
import tomllib
from importlib.resources import files
from pathlib import Path

from jinja2 import BaseLoader, Environment, FileSystemLoader, TemplateNotFound

CONFIG_PATH = Path("/etc/wgpeer/config.toml")
OVERRIDE_TEMPLATE_PATH = Path("/etc/wgpeer/client.conf.j2")

DEFAULTS: dict = {
    "server_ip": "",
    "server_port": 51820,
    "wg_interface": "wg0",
    "wg_dir": "/etc/wireguard",
    "subnet": "10.0.0.0/24",
    "dns": "10.0.0.1",
    "keepalive": 25,
}


def detect_public_ips() -> list[str]:
    """Return non-loopback, non-private IPv4 addresses from `ip -4 addr show`."""
    result = subprocess.run(
        ["ip", "-4", "addr", "show"],
        capture_output=True,
        text=True,
    )
    candidates = []
    for match in re.finditer(r"inet (\d+\.\d+\.\d+\.\d+)/", result.stdout):
        addr = match.group(1)
        try:
            ip = ipaddress.IPv4Address(addr)
        except ValueError:
            continue
        if not ip.is_loopback and not ip.is_private:
            candidates.append(addr)
    return candidates


def init_config(server_ip: str) -> None:
    """Write /etc/wgpeer/config.toml with the given server IP and defaults."""
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        f'server_ip = "{server_ip}"',
        f"server_port = {DEFAULTS['server_port']}",
        f'wg_interface = "{DEFAULTS["wg_interface"]}"',
        f'wg_dir = "{DEFAULTS["wg_dir"]}"',
        f'subnet = "{DEFAULTS["subnet"]}"',  # CIDR notation e.g. 10.0.0.0/24
        f'dns = "{DEFAULTS["dns"]}"',
        f"keepalive = {DEFAULTS['keepalive']}",
    ]
    CONFIG_PATH.write_text("\n".join(lines) + "\n")


def load_config() -> dict:
    """Load server config from /etc/wgpeer/config.toml, falling back to defaults."""
    cfg = dict(DEFAULTS)
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH, "rb") as f:
            cfg.update(tomllib.load(f))
    return cfg


class _PackageTemplateLoader(BaseLoader):
    """Load the bundled client.conf.j2 from the package."""

    def get_source(self, environment: Environment, template: str):
        pkg_templates = files("wgpeer") / "templates"
        path = pkg_templates / template
        try:
            source = path.read_text(encoding="utf-8")
        except (FileNotFoundError, TypeError):
            raise TemplateNotFound(template)
        return source, str(path), lambda: True


def _make_env() -> tuple[Environment, str]:
    """Return a Jinja2 Environment and the template name to use."""
    if OVERRIDE_TEMPLATE_PATH.exists():
        env = Environment(
            loader=FileSystemLoader(str(OVERRIDE_TEMPLATE_PATH.parent)),
            keep_trailing_newline=True,
        )
        return env, OVERRIDE_TEMPLATE_PATH.name
    env = Environment(loader=_PackageTemplateLoader(), keep_trailing_newline=True)
    return env, "client.conf.j2"


def render_client_config(
    private_key: str,
    ip: str,
    server_pub: str,
    cfg: dict,
) -> str:
    """Render the client WireGuard config from the Jinja2 template."""
    network = ipaddress.IPv4Network(cfg["subnet"], strict=False)
    env, template_name = _make_env()
    tmpl = env.get_template(template_name)
    return tmpl.render(
        private_key=private_key,
        ip=ip,
        prefix=network.prefixlen,
        dns=cfg["dns"],
        server_pub=server_pub,
        server_ip=cfg["server_ip"],
        port=cfg["server_port"],
        keepalive=cfg["keepalive"],
    )
