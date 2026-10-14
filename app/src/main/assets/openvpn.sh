#!/usr/bin/env bash
# Args: PROTO PORT.  Idempotent; never touches an OpenVPN setup it did not create.
. "$(dirname "$0")/lib.sh"
PROTO="${1:-}"; PORT="${2:-}"
[[ "$PROTO" =~ ^(udp|tcp)$ ]] || die 2 "Invalid protocol"
[[ "$PORT" =~ ^[0-9]{1,5}$ ]] && (( PORT >= 1 && PORT <= 65535 )) || die 2 "Invalid port"

MARK=/etc/openvpn/.ovpn-oneclick
SRV=/etc/openvpn/server
EASY=/etc/openvpn/easy-rsa-oneclick

step 1
check_server
MANAGED=0; [ -f "$MARK" ] && MANAGED=1
if [ "$MANAGED" -eq 0 ] && { [ -f "$SRV/server.conf" ] || [ -f /etc/openvpn/server.conf ]; }; then
  die 20 "An existing, unmanaged OpenVPN configuration was found. It was NOT modified."
fi
if [ "$MANAGED" -eq 1 ]; then echo "Reusing existing one-click installation"; fi
port_check "$PROTO" "$PORT" openvpn

step 2
apt_install openvpn easy-rsa iptables ca-certificates
OVPN_VER="$(openvpn --version | awk 'NR==1{print $2}')"
echo "OpenVPN $OVPN_VER installed"

step 3
export EASYRSA_BATCH=1 EASYRSA_ALGO=ec EASYRSA_CURVE=prime256v1 EASYRSA_REQ_CN="OneClick-CA"
if [ ! -x "$EASY/easyrsa" ]; then mkdir -p "$EASY"; cp -r /usr/share/easy-rsa/. "$EASY/"; fi
cd "$EASY"
[ -d pki ] || quiet ./easyrsa init-pki || die 50 "PKI init failed"
[ -f pki/ca.crt ] || quiet ./easyrsa build-ca nopass || die 50 "CA generation failed"
[ -f pki/issued/server.crt ] || quiet ./easyrsa build-server-full server nopass || die 50 "Server certificate failed"
install -d -m 755 "$SRV"
install -m 644 pki/ca.crt "$SRV/ca.crt"
install -m 644 pki/issued/server.crt "$SRV/server.crt"
install -m 600 pki/private/server.key "$SRV/server.key"
if [ ! -s "$SRV/tc.key" ]; then
  if ver_ge "$OVPN_VER" 2.5; then openvpn --genkey secret "$SRV/tc.key"; else openvpn --genkey --secret "$SRV/tc.key"; fi
fi
chmod 600 "$SRV/tc.key"
if ver_ge "$OVPN_VER" 2.5; then CIPHERS='data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305'
else CIPHERS='ncp-ciphers AES-256-GCM:AES-128-GCM'; fi
EXTRA=""; if [ "$PROTO" = udp ]; then EXTRA="explicit-exit-notify 1"; fi
cat > "$SRV/server.conf" <<CONF
port $PORT
proto $PROTO
dev tun
ca $SRV/ca.crt
cert $SRV/server.crt
key $SRV/server.key
dh none
ecdh-curve prime256v1
tls-crypt $SRV/tc.key
tls-version-min 1.2
cipher AES-256-GCM
$CIPHERS
auth SHA256
topology subnet
server 10.8.0.0 255.255.255.0
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS $DNS1"
push "dhcp-option DNS $DNS2"
keepalive 10 120
user nobody
group nogroup
persist-key
persist-tun
verb 3
$EXTRA
CONF
chmod 600 "$SRV/server.conf"
touch "$MARK"

step 4
enable_forwarding
fw_open "$PROTO" "$PORT"
fw_nat 10.8.0.0/24
fw_apply

step 5
systemctl enable openvpn-server@server >/dev/null 2>&1 || die 30 "Could not enable OpenVPN service"
if ! systemctl restart openvpn-server@server; then
  journalctl -u openvpn-server@server -n 15 --no-pager 2>&1 | sed 's/^/  /' || true
  die 30 "OpenVPN service failed to start"
fi
if ! wait_listening "$PROTO" "$PORT" openvpn || ! systemctl is-active --quiet openvpn-server@server; then
  journalctl -u openvpn-server@server -n 15 --no-pager 2>&1 | sed 's/^/  /' || true
  die 31 "OpenVPN is not listening on $PROTO/$PORT"
fi
echo "OpenVPN is running and listening on $PROTO/$PORT"

step 6
cd "$EASY"
[ ! -e "pki/issued/$CLIENT.crt" ] || die 70 "Client name already exists"
quiet ./easyrsa build-client-full "$CLIENT" nopass || die 50 "Client certificate generation failed"

step 7
umask 077
install -d -m 700 "$OUT_DIR"
OUT="$OUT_DIR/$CLIENT.ovpn"
CEXTRA=""; if [ "$PROTO" = udp ]; then CEXTRA="explicit-exit-notify"; fi
{
  cat <<PROFILE
client
dev tun
proto $PROTO
remote $ADDR $PORT
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
verify-x509-name server name
auth SHA256
cipher AES-256-GCM
tls-version-min 1.2
verb 3
$CEXTRA
PROFILE
  echo "<ca>";  cat "$SRV/ca.crt"; echo "</ca>"
  echo "<cert>"; sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' "pki/issued/$CLIENT.crt"; echo "</cert>"
  echo "<key>";  cat "pki/private/$CLIENT.key"; echo "</key>"
  echo "<tls-crypt>"; cat "$SRV/tc.key"; echo "</tls-crypt>"
} > "$OUT"
chmod 600 "$OUT"
if [ -n "${SUDO_USER:-}" ]; then chown "$SUDO_USER": "$OUT_DIR" "$OUT"; fi
echo "##FILE openvpn $OUT"
