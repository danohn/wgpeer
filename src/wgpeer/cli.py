"""CLI entry point for wgpeer."""

from __future__ import annotations

import os
import shutil
import sys

import click
from rich import print as rprint

from wgpeer.config import CONFIG_PATH, detect_public_ips, init_config
from wgpeer.peers import add_peer, list_peers, remove_peer, show_qr


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
    """Manage WireGuard peers on a Debian VPS."""


@cli.command()
def init() -> None:
    """Create /etc/wgpeer/config.toml, detecting or prompting for the server IP."""
    _require_root()

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
@click.argument("name")
def qr(name: str) -> None:
    """Display the QR code for an existing peer's config."""
    _require_root()
    show_qr(name)
