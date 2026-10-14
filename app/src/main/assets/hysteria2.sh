#!/usr/bin/env bash
# Args: PORT (UDP). Self-signed certificate; the client link pins its SHA-256 fingerprint.
. "$(dirname "$0")/lib.sh"
PORT="${1:-}"
[[ "$PORT" =~ ^[0-9]{1,5}$ ]] && (( PORT >= 1 && PORT <= 65535 )) || die 2 "Invalid port"
HD=/etc/hysteria-oneclick; BIN=/usr/local/bin/hysteria; SNI=oneclick.local

step 1
check_server
port_check udp "$PORT" hysteria

step 2
if [ -x "$BIN" ]; then
  echo "Hysteria2 already installed"
else
  apt_install curl openssl ca-certificates
  case "$(uname -m)" in x86_64|amd64) A=amd64 ;; aarch64|arm64) A=arm64 ;; *) die 10 "Unsupported CPU architecture" ;; esac
  T="$(mktemp -d)"; BASE=https://github.com/apernet/hysteria/releases/latest/download
  curl -fsSL --retry 3 -o "$T/h" "$BASE/hysteria-linux-$A" || { rm -rf "$T"; die 81 "Could not download Hysteria2"; }
  curl -fsSL --retry 3 -o "$T/hashes" "$BASE/hashes.txt" || { rm -rf "$T"; die 81 "Could not download the Hysteria2 checksums"; }
  EXP="$(grep "hysteria-linux-$A\$" "$T/hashes" | head -n1 | awk '{print $1}' | tr 'A-F' 'a-f' || true)"
  ACT="$(sha256sum "$T/h" | awk '{print $1}')"
  if [ -z "$EXP" ] || [ "$EXP" != "$ACT" ]; then rm -rf "$T"; die 81 "Hysteria2 checksum verification failed"; fi
  install -m 755 "$T/h" "$BIN"; rm -rf "$T"
  echo "Hysteria2 installed"
fi

step 3
install -d -m 750 "$HD"
if [ ! -s "$HD/server.key" ]; then
  openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$HD/server.key" -out "$HD/server.crt" -subj "/CN=$SNI" -days 3650 >/dev/null 2>&1 \
    || die 50 "Certificate generation failed"
fi
[ -s "$HD/password" ] || openssl rand -hex 16 > "$HD/password"
cat > "$HD/config.yaml" <<CONF
listen: :$PORT
tls:
  cert: $HD/server.crt
  key: $HD/server.key
auth:
  type: password
  password: $(cat "$HD/password")
CONF
chown -R root:nogroup "$HD"; chmod 640 "$HD"/server.key "$HD"/config.yaml "$HD"/password; chmod 644 "$HD/server.crt"

step 4
fw_open udp "$PORT"
fw_apply

step 5
cat > /etc/systemd/system/hysteria-oneclick.service <<UNIT
[Unit]
Description=Hysteria2 (one-click)
After=network-online.target
Wants=network-online.target

[Service]
User=nobody
Group=nogroup
ExecStart=$BIN server -c $HD/config.yaml
Restart=on-failure
LimitNOFILE=65535
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable hysteria-oneclick >/dev/null 2>&1 || die 30 "Could not enable Hysteria2"
if ! systemctl restart hysteria-oneclick; then
  journalctl -u hysteria-oneclick -n 12 --no-pager 2>&1 | sed 's/^/  /' || true
  die 30 "Hysteria2 failed to start"
fi
if ! wait_listening udp "$PORT" hysteria; then
  journalctl -u hysteria-oneclick -n 12 --no-pager 2>&1 | sed 's/^/  /' || true
  die 31 "Hysteria2 is not listening on udp/$PORT"
fi
echo "Hysteria2 is running on udp/$PORT"

step 6
FP="$(openssl x509 -noout -fingerprint -sha256 -in "$HD/server.crt" | cut -d= -f2)"
echo "##LINK hysteria2 hysteria2://$(cat "$HD/password")@$HOSTURI:$PORT/?insecure=1&sni=$SNI&pinSHA256=$FP#$(urlenc "$CLIENT-hysteria2")"
