#!/usr/bin/env bash
set -euo pipefail

# WireGuard server setup script (Debian/Ubuntu/RHEL/Fedora/Arch)
# - Installs WireGuard and tools
# - Generates server keys
# - Creates /etc/wireguard/wg0.conf
# - Enables IPv4 forwarding
# - Configures NAT rules using iptables (persisted where possible)
# - Enables and starts wg-quick@wg0

WG_IFACE="${WG_IFACE:-wg0}"
WG_PORT="${WG_PORT:-51820}"
WG_NET_CIDR="${WG_NET_CIDR:-10.8.0.0/24}"
SERVER_WG_IP="${SERVER_WG_IP:-10.8.0.1/24}"
WG_CONF_DIR="/etc/wireguard"
WG_CONF="${WG_CONF_DIR}/${WG_IFACE}.conf"
SERVER_PRIV_KEY_FILE="${WG_CONF_DIR}/server_private.key"
SERVER_PUB_KEY_FILE="${WG_CONF_DIR}/server_public.key"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root (sudo)."
  exit 1
fi

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

detect_os_family() {
  if command_exists apt-get; then
    echo "debian"
  elif command_exists dnf; then
    echo "rhel-dnf"
  elif command_exists yum; then
    echo "rhel-yum"
  elif command_exists pacman; then
    echo "arch"
  else
    echo "unknown"
  fi
}

install_packages() {
  local os
  os="$(detect_os_family)"

  case "$os" in
    debian)
      apt-get update
      apt-get install -y wireguard wireguard-tools iptables qrencode
      ;;
    rhel-dnf)
      dnf install -y wireguard-tools iptables qrencode
      ;;
    rhel-yum)
      yum install -y epel-release || true
      yum install -y wireguard-tools iptables qrencode
      ;;
    arch)
      pacman -Sy --noconfirm wireguard-tools iptables qrencode
      ;;
    *)
      echo "Unsupported distro. Install manually: wireguard-tools iptables qrencode"
      exit 1
      ;;
  esac
}

get_default_iface() {
  ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}'
}

enable_ipv4_forwarding() {
  local sysctl_file="/etc/sysctl.d/99-wireguard-forwarding.conf"
  echo "net.ipv4.ip_forward=1" > "$sysctl_file"
  sysctl -p "$sysctl_file" >/dev/null
}

save_iptables_rules_if_possible() {
  if command_exists netfilter-persistent; then
    netfilter-persistent save || true
  elif command_exists iptables-save; then
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4 || true
  fi
}

ensure_server_keys() {
  umask 077
  mkdir -p "$WG_CONF_DIR"

  if [[ ! -f "$SERVER_PRIV_KEY_FILE" ]]; then
    wg genkey > "$SERVER_PRIV_KEY_FILE"
  fi

  if [[ ! -f "$SERVER_PUB_KEY_FILE" ]]; then
    wg pubkey < "$SERVER_PRIV_KEY_FILE" > "$SERVER_PUB_KEY_FILE"
  fi

  chmod 600 "$SERVER_PRIV_KEY_FILE"
  chmod 644 "$SERVER_PUB_KEY_FILE"
}

write_wg_conf() {
  local ext_iface
  ext_iface="$(get_default_iface)"
  if [[ -z "$ext_iface" ]]; then
    echo "Could not detect external interface. Set manually in ${WG_CONF}."
    ext_iface="eth0"
  fi

  local server_priv
  server_priv="$(cat "$SERVER_PRIV_KEY_FILE")"

  cat > "$WG_CONF" <<CONF
[Interface]
Address = ${SERVER_WG_IP}
ListenPort = ${WG_PORT}
PrivateKey = ${server_priv}
SaveConfig = true

# NAT + forwarding for VPN clients
PostUp = iptables -A FORWARD -i ${WG_IFACE} -j ACCEPT; iptables -A FORWARD -o ${WG_IFACE} -j ACCEPT; iptables -t nat -A POSTROUTING -s ${WG_NET_CIDR} -o ${ext_iface} -j MASQUERADE
PostDown = iptables -D FORWARD -i ${WG_IFACE} -j ACCEPT; iptables -D FORWARD -o ${WG_IFACE} -j ACCEPT; iptables -t nat -D POSTROUTING -s ${WG_NET_CIDR} -o ${ext_iface} -j MASQUERADE
CONF

  chmod 600 "$WG_CONF"
}

enable_and_start_service() {
  systemctl enable "wg-quick@${WG_IFACE}"
  systemctl restart "wg-quick@${WG_IFACE}"
}

main() {
  install_packages
  ensure_server_keys
  enable_ipv4_forwarding
  write_wg_conf
  enable_and_start_service
  save_iptables_rules_if_possible

  echo
  echo "WireGuard server setup complete."
  echo "Interface: ${WG_IFACE}"
  echo "Config: ${WG_CONF}"
  echo "Server public key: $(cat "$SERVER_PUB_KEY_FILE")"
  echo
  echo "Next: run ./generate-wireguard-client.sh <client_name> <server_public_ip_or_dns>"
}

main "$@"
