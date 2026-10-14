#!/usr/bin/env bash
# Args: PORT MTU.  Adds a new peer on every run; never touches a wg0 it did not create.
. "$(dirname "$0")/lib.sh"
PORT="${1:-}"; MTU="${2:-}"
[[ "$PORT" =~ ^[0-9]{1,5}$ ]] && (( PORT >= 1 && PORT <= 65535 )) || die 2 "Invalid port"
[[ "$MTU" =~ ^[0-9]{4}$ ]] && (( MTU >= 1280 && MTU <= 1500 )) || die 2 "Invalid MTU"

WGD=/etc/wireguard
CONF=$WGD/wg0.conf
SUBNET=10.9.0

step 1
check_server
if [ -f "$CONF" ] && ! grep -q '^# oneclick-managed' "$CONF"; then
  die 20 "An existing, unmanaged WireGuard wg0 configuration was found. It was NOT modified."
fi
if ! ip link show wg0 >/dev/null 2>&1; then port_check udp "$PORT" "-none-"; fi

step 2
apt_install wireguard wireguard-tools iptables
echo "WireGuard tools installed"

step 3
umask 077
install -d -m 700 "$WGD"
[ -s "$WGD/oneclick_server.key" ] || wg genkey > "$WGD/oneclick_server.key"
wg pubkey < "$WGD/oneclick_server.key" > "$WGD/oneclick_server.pub"
if [ ! -f "$CONF" ]; then
  cat > "$CONF" <<WG
# oneclick-managed
[Interface]
Address = $SUBNET.1/24
ListenPort = $PORT
PrivateKey = $(cat "$WGD/oneclick_server.key")
WG
else
  sed -i "s/^ListenPort.*/ListenPort = $PORT/" "$CONF"
fi
chmod 600 "$CONF"

step 4
enable_forwarding
fw_open udp "$PORT"
fw_nat "$SUBNET.0/24"
fw_apply

step 5
systemctl enable wg-quick@wg0 >/dev/null 2>&1 || die 30 "Could not enable WireGuard"
systemctl restart wg-quick@wg0 || { journalctl -u wg-quick@wg0 -n 12 --no-pager 2>&1 | sed 's/^/  /' || true; die 30 "WireGuard failed to start (kernel module or TUN support missing?)"; }
for _ in $(seq 1 10); do if ss -Hlnu "sport = :$PORT" 2>/dev/null | grep -q .; then WGOK=1; break; fi; sleep 1; done
[ "${WGOK:-0}" = 1 ] || die 31 "WireGuard is not listening on udp/$PORT"
echo "WireGuard is up on udp/$PORT"

step 6
PEERS="$(grep -c '^\[Peer\]' "$CONF" || true)"
IDX=$(( PEERS + 2 ))
(( IDX <= 254 )) || die 71 "Too many WireGuard peers"
CPRIV="$(wg genkey)"; CPUB="$(printf '%s' "$CPRIV" | wg pubkey)"; PSK="$(wg genpsk)"
cat >> "$CONF" <<PEER

[Peer]
# $CLIENT
PublicKey = $CPUB
PresharedKey = $PSK
AllowedIPs = $SUBNET.$IDX/32
PEER
wg syncconf wg0 <(wg-quick strip wg0) || die 32 "Could not add the client peer"

install -d -m 700 "$OUT_DIR"
OUT="$OUT_DIR/$CLIENT-wg.conf"
cat > "$OUT" <<CLIENTCONF
[Interface]
PrivateKey = $CPRIV
Address = $SUBNET.$IDX/32
DNS = $DNS1, $DNS2
MTU = $MTU

[Peer]
PublicKey = $(cat "$WGD/oneclick_server.pub")
PresharedKey = $PSK
Endpoint = $HOSTURI:$PORT
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
CLIENTCONF
chmod 600 "$OUT"
if [ -n "${SUDO_USER:-}" ]; then chown "$SUDO_USER": "$OUT_DIR" "$OUT"; fi
echo "##FILE wireguard $OUT"
