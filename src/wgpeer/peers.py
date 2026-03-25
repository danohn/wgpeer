"""Add, remove, and list WireGuard peers."""

from __future__ import annotations

import logging
import re
import subprocess
from pathlib import Path

from rich import print as rprint
from rich.table import Table

from wgpeer.config import load_config, render_client_config
from wgpeer.keys import gen_keypair, run
from wgpeer.network import next_ip

LOG_PATH = Path("/var/log/wgpeer.log")
NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")


def _setup_logger() -> logging.Logger:
    logger = logging.getLogger("wgpeer")
    if not logger.handlers:
        handler = logging.FileHandler(LOG_PATH)
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(message)s", datefmt="%Y-%m-%dT%H:%M:%S")
        )
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger


def validate_name(name: str) -> None:
    """Raise SystemExit if the peer name contains invalid characters."""
    if not NAME_RE.match(name):
        rprint(
            f"[red]Invalid peer name '{name}'. "
            "Use only letters, digits, hyphens, and underscores.[/red]"
        )
        raise SystemExit(1)


def _conf_path(name: str, wg_dir: str) -> Path:
    return Path(wg_dir) / f"{name}.conf"


def _server_pubkey(cfg: dict) -> str:
    """Read the server's public key from the WireGuard interface."""
    result = subprocess.run(
        ["wg", "show", cfg["wg_interface"], "public-key"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0 or not result.stdout.strip():
        rprint(
            "[red]Could not retrieve server public key from WireGuard interface.[/red]"
        )  # noqa: E501
        raise SystemExit(1)
    return result.stdout.strip()


def add_peer(name: str) -> None:
    """Add a new WireGuard peer."""
    validate_name(name)
    cfg = load_config()
    conf = _conf_path(name, cfg["wg_dir"])

    if not cfg.get("server_ip"):
        rprint("[red]server_ip is not set. Run 'wgpeer init' first.[/red]")
        raise SystemExit(1)

    if conf.exists():
        rprint(f"[red]Peer '{name}' already exists ({conf}).[/red]")
        raise SystemExit(1)

    ip = next_ip(subnet=cfg["subnet"], interface=cfg["wg_interface"])
    priv, pub = gen_keypair()
    server_pub = _server_pubkey(cfg)

    content = render_client_config(
        private_key=priv,
        ip=ip,
        server_pub=server_pub,
        cfg=cfg,
    )

    conf.write_text(content)
    conf.chmod(0o600)

    run(["wg", "set", cfg["wg_interface"], "peer", pub, "allowed-ips", f"{ip}/32"])
    run(["wg-quick", "save", cfg["wg_interface"]])

    import segno

    qr = segno.make(content)
    qr.terminal(compact=True)

    rprint(f"[green]Peer '{name}' added with IP {ip}.[/green]")

    logger = _setup_logger()
    logger.info("ADD name=%s ip=%s pubkey=%s", name, ip, pub)


def remove_peer(name: str) -> None:
    """Remove an existing WireGuard peer."""
    validate_name(name)
    cfg = load_config()
    conf = _conf_path(name, cfg["wg_dir"])

    if not conf.exists():
        rprint(f"[red]Peer '{name}' not found ({conf}).[/red]")
        raise SystemExit(1)

    # Extract PrivateKey from conf to derive public key
    pub = _pubkey_from_conf(conf)

    run(["wg", "set", cfg["wg_interface"], "peer", pub, "remove"])
    run(["wg-quick", "save", cfg["wg_interface"]])
    conf.unlink()

    rprint(f"[green]Peer '{name}' removed.[/green]")

    logger = _setup_logger()
    logger.info("REMOVE name=%s pubkey=%s", name, pub)


def _pubkey_from_conf(conf: Path) -> str:
    """Derive the public key by reading PrivateKey from a .conf file."""
    for line in conf.read_text().splitlines():
        line = line.strip()
        if line.lower().startswith("privatekey"):
            _, _, priv = line.partition("=")
            priv = priv.strip()
            result = subprocess.run(
                ["wg", "pubkey"],
                input=priv,
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                rprint("[red]Failed to derive public key from private key.[/red]")
                raise SystemExit(1)
            return result.stdout.strip()
    rprint(f"[red]No PrivateKey found in {conf}.[/red]")
    raise SystemExit(1)


def list_peers() -> None:
    """List all WireGuard peers in a Rich table."""
    cfg = load_config()
    wg_dir = Path(cfg["wg_dir"])

    result = subprocess.run(
        ["wg", "show", cfg["wg_interface"], "allowed-ips"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        rprint("[red]Failed to read WireGuard peers.[/red]")
        raise SystemExit(1)

    # Build pubkey -> ip map from wg show output
    pub_to_ip: dict[str, str] = {}
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            pub_to_ip[parts[0]] = parts[1].split("/")[0]

    table = Table(title="WireGuard Peers")
    table.add_column("Name", style="cyan")
    table.add_column("IP", style="magenta")
    table.add_column("Public Key", style="yellow")

    for conf_file in sorted(wg_dir.glob("*.conf")):
        peer_name = conf_file.stem
        try:
            pub = _pubkey_from_conf(conf_file)
        except SystemExit:
            pub = "unknown"
        ip = pub_to_ip.get(pub, "not active")
        table.add_row(peer_name, ip, pub)

    from rich import get_console

    get_console().print(table)


def show_qr(name: str) -> None:
    """Display the QR code for an existing peer config."""
    validate_name(name)
    cfg = load_config()
    conf = _conf_path(name, cfg["wg_dir"])

    if not conf.exists():
        rprint(f"[red]Peer '{name}' not found ({conf}).[/red]")
        raise SystemExit(1)

    content = conf.read_text()
    import segno

    qr = segno.make(content)
    qr.terminal(compact=True)
