"""WireGuard key generation."""

from __future__ import annotations

import subprocess


def run(cmd: list[str], input: str | None = None) -> subprocess.CompletedProcess:
    """Run a shell command, raising SystemExit on failure."""
    result = subprocess.run(
        cmd,
        input=input,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        from rich import print as rprint

        rprint(f"[red]Error running {' '.join(cmd)}: {result.stderr.strip()}[/red]")
        raise SystemExit(1)
    return result


def genkey() -> str:
    """Generate a WireGuard private key."""
    return run(["wg", "genkey"]).stdout.strip()


def pubkey(private_key: str) -> str:
    """Derive the WireGuard public key from a private key."""
    return run(["wg", "pubkey"], input=private_key).stdout.strip()


def gen_keypair() -> tuple[str, str]:
    """Generate a (private_key, public_key) pair."""
    priv = genkey()
    pub = pubkey(priv)
    return priv, pub
