"""CLI entry point for wgpeer."""

from __future__ import annotations

import os
import shutil
import sys

import click
from rich import print as rprint

from wgpeer.config import (
    CONFIG_PATH,
    detect_outbound_iface,
    detect_public_ips,
    init_config,
    init_server_config,
    load_config,
)
from wgpeer.keys import gen_keypair, run
from wgpeer.peers import add_peer, list_peers, peer_status, remove_peer, show_qr


def _require_root() -> None:
    if os.geteuid() != 0:
        rprint("[red]wgpeer must be run as root.[/red]")
        sys.exit(1)


def _require_wg() -> None:
    if shutil.which("wg") is None:
        rprint("[red]'wg' not found in PATH. Is WireGuard installed?[/red]")
        sys.exit(1)


@click.group()
def cli() -> None:
    """Manage WireGuard peers."""


@cli.command()
def init() -> None:
    """Set up wgpeer: create config.toml and optionally the WireGuard server config."""
    _require_root()

    # --- Step 1: config.toml ---
    if CONFIG_PATH.exists():
        click.confirm(f"{CONFIG_PATH} already exists. Overwrite?", abort=True)

    candidates = detect_public_ips()
    if candidates:
        detected = candidates[0]
        rprint(f"Detected public IP: [cyan]{detected}[/cyan]")
        server_ip = click.prompt("Server IP", default=detected)
    else:
        rprint("[yellow]Could not detect a public IP from 'ip a'.[/yellow]")
        server_ip = click.prompt("Enter your server's public IP")

    init_config(server_ip)
    rprint(f"[green]Config written to {CONFIG_PATH}.[/green]")

    # --- Step 2: wg0.conf ---
    cfg = load_config()
    wg_interface = cfg["wg_interface"]
    wg_dir = cfg["wg_dir"]
    server_conf = os.path.join(wg_dir, f"{wg_interface}.conf")

    if os.path.exists(server_conf):
        rprint(f"[dim]{server_conf} already exists, skipping.[/dim]")
        return

    if not click.confirm(f"\n{server_conf} not found. Create it now?", default=True):
        return

    # Detect outbound interface
    detected_iface = detect_outbound_iface()
    if detected_iface:
        rprint(f"Detected outbound interface: [cyan]{detected_iface}[/cyan]")
        outbound_iface = click.prompt(
            "Outbound network interface", default=detected_iface
        )
    else:
        rprint("[yellow]Could not detect outbound interface.[/yellow]")
        outbound_iface = click.prompt(
            "Enter your outbound network interface (e.g. eth0)"
        )

    # Masquerade explanation and prompt
    rprint(
        "\n[bold]IP Masquerade (NAT)[/bold] allows connected peers to route all their "
        "internet traffic through this server, acting as a traditional VPN. "
        "Without it, peers can only reach other devices on the WireGuard subnet."
    )
    masquerade = click.confirm("Enable IP masquerade?", default=True)

    # Generate server keypair
    priv, pub = gen_keypair()
    rprint(f"\nServer public key: [cyan]{pub}[/cyan]")

    init_server_config(
        wg_interface=wg_interface,
        wg_dir=wg_dir,
        subnet=cfg["subnet"],
        port=cfg["server_port"],
        private_key=priv,
        outbound_iface=outbound_iface,
        masquerade=masquerade,
    )
    rprint(f"[green]{server_conf} written.[/green]")

    if click.confirm(f"\nBring up {wg_interface} now?", default=True):
        _require_wg()
        run(["wg-quick", "up", wg_interface])
        rprint(f"[green]{wg_interface} is up.[/green]")


@cli.command()
@click.argument("name")
def add(name: str) -> None:
    """Add a new peer with an auto-assigned IP and display its QR code."""
    _require_root()
    _require_wg()
    add_peer(name)


@cli.command()
@click.argument("name")
def remove(name: str) -> None:
    """Remove an existing peer and delete its config file."""
    _require_root()
    _require_wg()
    remove_peer(name)


@cli.command(name="list")
def list_cmd() -> None:
    """List all peers with their IPs and public keys."""
    _require_root()
    _require_wg()
    list_peers()


@cli.command()
def status() -> None:
    """Show live status (handshake time, transfer) for all peers."""
    _require_root()
    _require_wg()
    peer_status()


@cli.command()
@click.argument("name")
def qr(name: str) -> None:
    """Display the QR code for an existing peer's config."""
    _require_root()
    show_qr(name)
