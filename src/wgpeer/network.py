"""IP address assignment logic."""

from __future__ import annotations

import subprocess


def _get_allowed_ips(interface: str = "wg0") -> list[str]:
    """Return all allowed-ips entries from `wg show <interface> allowed-ips`."""
    result = subprocess.run(
        ["wg", "show", interface, "allowed-ips"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return []
    ips = []
    for line in result.stdout.splitlines():
        # Each line: <pubkey>\t<ip/mask> [<ip/mask> ...]
        parts = line.split()
        if len(parts) >= 2:
            for addr in parts[1:]:
                ips.append(addr.split("/")[0])
    return ips


def next_ip(subnet: str = "10.0.0", interface: str = "wg0") -> str:
    """Return the next available peer IP in the given subnet.

    Reads current allocations from the WireGuard interface and returns
    the next free address after the highest last octet found.
    Falls back to <subnet>.2 if no peers exist.
    """
    existing = _get_allowed_ips(interface)

    last_octets: list[int] = []
    for ip in existing:
        if ip.startswith(subnet + "."):
            try:
                last_octets.append(int(ip.split(".")[-1]))
            except ValueError:
                pass

    if not last_octets:
        return f"{subnet}.2"

    highest = max(last_octets)
    if highest >= 254:
        from rich import print as rprint

        rprint(f"[red]Subnet {subnet}.0/24 is full (no addresses left)[/red]")
        raise SystemExit(1)

    return f"{subnet}.{highest + 1}"
