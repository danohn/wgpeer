# wgpeer

Manage WireGuard peers.

## Installation

```bash
uv tool install wgpeer
```

Or run without installing:

```bash
uvx wgpeer --help
```

## Usage

Must be run as root with WireGuard installed.

On first use, run `init` to create the config file:

```bash
sudo wgpeer init
```

This detects your server's public IP from `ip a` and writes `/etc/wgpeer/config.toml`. You'll be prompted to confirm or enter the IP manually if none is detected.

```bash
sudo wgpeer add <name>     # Add a new peer (auto-assigns IP, shows QR code)
sudo wgpeer remove <name>  # Remove an existing peer
sudo wgpeer list           # List all peers with IPs and public keys
sudo wgpeer qr <name>      # Display QR code for an existing peer
```

## Configuration

Server settings are stored in `/etc/wgpeer/config.toml` (created by `wgpeer init`). All fields except `server_ip` have defaults:

```toml
server_ip = "1.2.3.4"
server_port = 51820
wg_interface = "wg0"
wg_dir = "/etc/wireguard"
subnet = "10.0.0.0/24"
dns = "10.0.0.1"
keepalive = 25
```

## Template Override

To customise the client config template, place a Jinja2 template at `/etc/wgpeer/client.conf.j2`. Available variables: `private_key`, `ip`, `dns`, `server_pub`, `server_ip`, `port`, `keepalive`.

## Building and Publishing

```bash
uv build
uv publish
```
