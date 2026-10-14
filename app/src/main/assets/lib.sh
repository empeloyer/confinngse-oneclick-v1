#!/usr/bin/env bash
# Shared helpers, sourced by the protocol scripts.
# App protocol lines:  ##STEP n   ##ERR msg   ##FILE <id> <path>   ##LINK <id> <url>
# Env (validated here): ADDR CLIENT OUT_DIR DNS1 DNS2
set -Eeuo pipefail
export DEBIAN_FRONTEND=noninteractive

step() { echo "##STEP $1"; }
die()  { echo "##ERR $2"; exit "$1"; }
trap 'echo "##ERR Unexpected failure at line $LINENO"' ERR
quiet() { local o; if ! o="$("$@" 2>&1)"; then echo "$o" | tail -n 8; return 1; fi; }
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]; }

ADDR="${ADDR:-}"; CLIENT="${CLIENT:-}"; OUT_DIR="${OUT_DIR:-/root/ovpn-clients}"
DNS1="${DNS1:-1.1.1.1}"; DNS2="${DNS2:-1.0.0.1}"
[[ "$ADDR" =~ ^[A-Za-z0-9.:-]{1,253}$ ]] || die 2 "Invalid server address"
[[ "$CLIENT" =~ ^[A-Za-z0-9_-]{1,40}$ ]] || die 2 "Invalid client name"
[[ "$OUT_DIR" =~ ^/[A-Za-z0-9_./-]+$ ]] || die 2 "Unsupported output directory path"
[[ "$DNS1" =~ ^[0-9.]{7,15}$ && "$DNS2" =~ ^[0-9.]{7,15}$ ]] || die 2 "Invalid DNS address"
HOSTURI="$ADDR"; if [[ "$ADDR" == *:* ]]; then HOSTURI="[$ADDR]"; fi

check_server() {
  [ "$(id -u)" -eq 0 ] || die 11 "Root privileges required (use root or a passwordless-sudo user)"
  # shellcheck disable=SC1091
  . /etc/os-release
  case "${ID:-}" in
    ubuntu|debian) echo "OS: ${PRETTY_NAME:-$ID}" ;;
    *) die 10 "Unsupported OS: ${PRETTY_NAME:-unknown} (Ubuntu or Debian required)" ;;
  esac
  command -v apt-get >/dev/null || die 10 "apt-get not found"
}

apt_install() {
  apt-get -o DPkg::Lock::Timeout=180 update -qq || die 40 "apt-get update failed"
  apt-get -o DPkg::Lock::Timeout=180 install -y -qq "$@" >/dev/null || die 40 "Package installation failed"
}

# port_check <udp|tcp> <port> <process-name>: fail if another program owns the port
port_check() {
  local t=t l; [ "$1" = udp ] && t=u
  l="$(ss -Hlnp"$t" "sport = :$2" 2>/dev/null || true)"
  if [ -n "$l" ] && ! grep -q "\"$3\"" <<<"$l"; then die 21 "Port $2/$1 is already used by another service"; fi
}
port_listening() { local t=t; [ "$1" = udp ] && t=u; ss -Hlnp"$t" "sport = :$2" 2>/dev/null | grep -q "\"$3\""; }
wait_listening() { local _; for _ in $(seq 1 15); do if port_listening "$@"; then return 0; fi; sleep 1; done; return 1; }

# ---- shared firewall: rules are collected in rules.list and applied by one systemd unit ----
FW_DIR=/etc/oneclick
fw_add() {
  install -d -m 755 "$FW_DIR"; touch "$FW_DIR/rules.list"
  grep -qxF "$1" "$FW_DIR/rules.list" || echo "$1" >> "$FW_DIR/rules.list"
}
fw_open() { # <udp|tcp> <port>
  fw_add "port $1 $2"
  if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
    ufw allow "$2/$1" >/dev/null || echo "Warning: ufw rule failed"
  fi
}
fw_nat() { fw_add "nat $1"; }
enable_forwarding() {
  echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-oneclick.conf
  sysctl -p /etc/sysctl.d/99-oneclick.conf >/dev/null
}
fw_apply() {
  local iface
  iface="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
  [ -n "$iface" ] && [[ "$iface" =~ ^[A-Za-z0-9_.:-]+$ ]] || die 60 "Could not detect the public network interface"
  install -d -m 755 "$FW_DIR"; touch "$FW_DIR/rules.list"
  cat > "$FW_DIR/fw.sh" <<FW
#!/bin/sh
IFACE=$iface
rule() { t="\$1"; shift; iptables -t "\$t" -C "\$@" 2>/dev/null || iptables -t "\$t" -I "\$@"; }
rule filter FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
rule filter INPUT -i tun+ -j ACCEPT
rule filter INPUT -i wg+ -j ACCEPT
while read -r kind a b; do
  case "\$kind" in
    port) rule filter INPUT -p "\$a" --dport "\$b" -j ACCEPT ;;
    nat) rule nat POSTROUTING -s "\$a" -o "\$IFACE" -j MASQUERADE; rule filter FORWARD -s "\$a" -j ACCEPT ;;
  esac
done < $FW_DIR/rules.list
FW
  chmod 700 "$FW_DIR/fw.sh"
  cat > /etc/systemd/system/oneclick-fw.service <<'UNIT'
[Unit]
Description=One-click firewall rules
After=network-online.target
Wants=network-online.target
Before=openvpn-server@server.service wg-quick@wg0.service xray-oneclick.service hysteria-oneclick.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/etc/oneclick/fw.sh

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable oneclick-fw.service >/dev/null 2>&1 || true
  systemctl restart oneclick-fw.service || die 61 "Firewall rules could not be applied"
}

urlenc() {
  local s="$1" o="" c i
  for ((i = 0; i < ${#s}; i++)); do
    c="${s:i:1}"
    case "$c" in
      [A-Za-z0-9._~-]) o+="$c" ;;
      *) o+="$(printf '%%%02X' "'$c")" ;;
    esac
  done
  printf '%s' "$o"
}
b64url() { printf '%s' "$1" | base64 -w0 | tr '+/' '-_' | tr -d '='; }
