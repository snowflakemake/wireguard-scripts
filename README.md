# WireGuard Server + Client Scripts + Web UI

Small toolkit to set up a WireGuard server and generate client configs using either shell scripts or a simple browser UI.

## Included Files

- `setup-wireguard-server.sh`:
  - Installs WireGuard tools
  - Creates server keys
  - Writes `/etc/wireguard/wg0.conf` (or custom interface)
  - Enables IPv4 forwarding and NAT
  - Starts `wg-quick@<iface>`
- `generate-wireguard-client.sh`:
  - Generates client keypair and config
  - Adds the peer to server config and running interface
  - Restarts `wg-quick@<iface>`
  - Prints QR code for mobile clients
- `web-ui.py`:
  - Local web interface for non-technical personnel
  - Wraps both scripts with forms and output logs

## Requirements

- Linux host (Debian/Ubuntu, RHEL/Fedora, Arch supported by setup script)
- Root privileges (`sudo`) for setup/client operations
- Open UDP port for WireGuard (default `51820`)

## Quick Start (CLI)

1. Set up the server:

```bash
cd /home/user/projects/wireguard-scripts
sudo ./setup-wireguard-server.sh
```

2. Generate first client:

```bash
sudo ./generate-wireguard-client.sh alice vpn.example.com
```

Client config is saved under `/etc/wireguard/clients/alice.conf`.

## CLI Usage Details

### `setup-wireguard-server.sh`

Optional environment variables:

- `WG_IFACE` (default: `wg0`)
- `WG_PORT` (default: `51820`)
- `WG_NET_CIDR` (default: `10.8.0.0/24`)
- `SERVER_WG_IP` (default: `10.8.0.1/24`)

Example:

```bash
sudo WG_IFACE=wg0 WG_PORT=51820 WG_NET_CIDR=10.8.0.0/24 SERVER_WG_IP=10.8.0.1/24 ./setup-wireguard-server.sh
```

### `generate-wireguard-client.sh`

Usage:

```bash
sudo ./generate-wireguard-client.sh <client_name> <server_endpoint_host_or_ip> [dns] [client_ip]
```

Example:

```bash
sudo ./generate-wireguard-client.sh bob vpn.example.com 1.1.1.1 10.8.0.10/32
```

Notes:

- If `client_ip` is omitted, script auto-picks next free `10.8.0.X/32`.
- Existing client name is rejected to prevent accidental overwrite.

## Web UI (Non-Technical Workflow)

Start UI (must run as root because backend scripts require root):

```bash
cd /home/user/projects/wireguard-scripts
sudo ./web-ui.py --host 127.0.0.1 --port 8080
```

Open in browser:

- `http://127.0.0.1:8080`

UI sections:

1. **Generate Client** (`/`)
2. **Current Clients List** (`/clients`) with remove action
3. **Client Removal Confirmation**: type exact client name before deletion
4. **Client QR Code** (rendered image for mobile scan after creation)
5. **Last Action Output** (success/error + full log)

If staff need remote access, use `--host 0.0.0.0` and protect access with firewall/VPN/reverse proxy auth.

## Important Paths

- Server config: `/etc/wireguard/<iface>.conf`
- Server keys:
  - `/etc/wireguard/server_private.key`
  - `/etc/wireguard/server_public.key`
- Client files: `/etc/wireguard/clients/`

## Security Notes

- Keep this repository and host access restricted.
- Treat `/etc/wireguard/clients/*.conf` as sensitive secrets.
- Do not expose the web UI publicly without authentication and network controls.
- Input validation in UI is basic and not a security boundary.

## Troubleshooting

- `Run as root (sudo).`
  - Start scripts/UI with `sudo`.
- `wg not found` or `qrencode not found`
  - Run server setup script first, or install required packages manually.
- `Server config not found: /etc/wireguard/wg0.conf`
  - Run setup before generating clients.
- Clients connect but no internet access
  - Verify IP forwarding and NAT rules are active, and UDP `51820` is open.

## Stop/Restart Services

Check status:

```bash
sudo systemctl status wg-quick@wg0
```

Restart:

```bash
sudo systemctl restart wg-quick@wg0
```
