#!/usr/bin/env bash
set -euo pipefail

# Generate and register a new WireGuard client against local wg0 server config.
# Usage:
#   sudo ./generate-wireguard-client.sh <client_name> <server_endpoint_host_or_ip> [dns] [client_ip]
# Example:
#   sudo ./generate-wireguard-client.sh alice vpn.example.com 1.1.1.1 10.8.0.2/32

WG_IFACE="${WG_IFACE:-wg0}"
WG_CONF_DIR="/etc/wireguard"
WG_CONF="${WG_CONF_DIR}/${WG_IFACE}.conf"
CLIENTS_DIR="${WG_CONF_DIR}/clients"
SERVER_PUB_KEY_FILE="${WG_CONF_DIR}/server_public.key"
WG_PORT="${WG_PORT:-51820}"
DEFAULT_DNS="${DEFAULT_DNS:-1.1.1.1}"
DEFAULT_ALLOWED_IPS="${DEFAULT_ALLOWED_IPS:-0.0.0.0/0, ::/0}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root (sudo)."
  exit 1
fi

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <client_name> <server_endpoint_host_or_ip> [dns] [client_ip]"
  exit 1
fi

CLIENT_NAME="$1"
SERVER_ENDPOINT_HOST="$2"
DNS_SERVER="${3:-$DEFAULT_DNS}"
REQUESTED_CLIENT_IP="${4:-}"

command -v wg >/dev/null 2>&1 || { echo "wg not found. Install wireguard-tools first."; exit 1; }
command -v qrencode >/dev/null 2>&1 || { echo "qrencode not found. Install qrencode first."; exit 1; }

if [[ ! -f "$WG_CONF" ]]; then
  echo "Server config not found: $WG_CONF"
  exit 1
fi

if [[ ! -f "$SERVER_PUB_KEY_FILE" ]]; then
  echo "Server public key file missing: $SERVER_PUB_KEY_FILE"
  exit 1
fi

mkdir -p "$CLIENTS_DIR"
umask 077

CLIENT_PRIV_KEY_FILE="${CLIENTS_DIR}/${CLIENT_NAME}.private.key"
CLIENT_PUB_KEY_FILE="${CLIENTS_DIR}/${CLIENT_NAME}.public.key"
CLIENT_CONF_FILE="${CLIENTS_DIR}/${CLIENT_NAME}.conf"

if [[ -f "$CLIENT_CONF_FILE" ]]; then
  echo "Client config already exists: $CLIENT_CONF_FILE"
  exit 1
fi

next_client_ip() {
  # Picks next free IP in 10.8.0.X range based on existing AllowedIPs entries.
  local used
  used="$(grep -E '^AllowedIPs\s*=\s*10\.8\.0\.[0-9]+/32' "$WG_CONF" | sed -E 's/.*10\.8\.0\.([0-9]+)\/32/\1/' | sort -n | uniq || true)"

  local i
  for i in $(seq 2 254); do
    if ! grep -qx "$i" <<< "$used"; then
      echo "10.8.0.${i}/32"
      return 0
    fi
  done

  return 1
}

CLIENT_IP="${REQUESTED_CLIENT_IP:-$(next_client_ip || true)}"
if [[ -z "$CLIENT_IP" ]]; then
  echo "No free client IP found. Provide one manually as 4th argument (e.g., 10.8.0.42/32)."
  exit 1
fi

wg genkey > "$CLIENT_PRIV_KEY_FILE"
wg pubkey < "$CLIENT_PRIV_KEY_FILE" > "$CLIENT_PUB_KEY_FILE"

CLIENT_PRIV_KEY="$(cat "$CLIENT_PRIV_KEY_FILE")"
CLIENT_PUB_KEY="$(cat "$CLIENT_PUB_KEY_FILE")"
SERVER_PUB_KEY="$(cat "$SERVER_PUB_KEY_FILE")"

cat > "$CLIENT_CONF_FILE" <<CONF
[Interface]
PrivateKey = ${CLIENT_PRIV_KEY}
Address = ${CLIENT_IP}
DNS = ${DNS_SERVER}

[Peer]
PublicKey = ${SERVER_PUB_KEY}
Endpoint = ${SERVER_ENDPOINT_HOST}:${WG_PORT}
AllowedIPs = ${DEFAULT_ALLOWED_IPS}
PersistentKeepalive = 25
CONF

chmod 600 "$CLIENT_CONF_FILE" "$CLIENT_PRIV_KEY_FILE"
chmod 644 "$CLIENT_PUB_KEY_FILE"

# Register peer in running interface and persist into server config.
wg set "$WG_IFACE" peer "$CLIENT_PUB_KEY" allowed-ips "$CLIENT_IP"

cat >> "$WG_CONF" <<PEER

# ${CLIENT_NAME}
[Peer]
PublicKey = ${CLIENT_PUB_KEY}
AllowedIPs = ${CLIENT_IP}
PEER

systemctl restart "wg-quick@${WG_IFACE}"

echo
echo "Client created: ${CLIENT_NAME}"
echo "Client IP: ${CLIENT_IP}"
echo "Client config: ${CLIENT_CONF_FILE}"
echo
echo "Scan QR code on mobile client:"
qrencode -t ansiutf8 < "$CLIENT_CONF_FILE"
echo
echo "Raw config:"
cat "$CLIENT_CONF_FILE"
