"""IP address assignment logic."""

from __future__ import annotations

import ipaddress
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


def next_ip(subnet: str = "10.0.0.0/24", interface: str = "wg0") -> str:
    """Return the next available peer IP in the given subnet.

    Reads current allocations from the WireGuard interface and returns
    the next free address after the highest allocated host. Falls back
    to the second host in the subnet (e.g. 10.0.0.2) if no peers exist,
    reserving the first host for the server/gateway.
    """
    network = ipaddress.IPv4Network(subnet, strict=False)
    existing = _get_allowed_ips(interface)

    allocated: list[ipaddress.IPv4Address] = []
    for raw in existing:
        try:
            addr = ipaddress.IPv4Address(raw)
        except ValueError:
            continue
        if addr in network:
            allocated.append(addr)

    hosts = list(network.hosts())  # excludes network and broadcast addresses
    if len(hosts) < 2:
        from rich import print as rprint

        rprint(f"[red]Subnet {subnet} is too small to assign peer addresses.[/red]")
        raise SystemExit(1)

    # Reserve the first host for the server/gateway
    if not allocated:
        return str(hosts[1])

    highest = max(allocated)
    next_addr = highest + 1

    if next_addr not in network or next_addr == network.broadcast_address:
        from rich import print as rprint

        rprint(f"[red]Subnet {subnet} is full (no addresses left).[/red]")
        raise SystemExit(1)

    return str(next_addr)
