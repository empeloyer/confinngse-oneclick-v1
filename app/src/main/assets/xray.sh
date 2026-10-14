#!/usr/bin/env bash
# Args: one spec per inbound:  <kind>:<port>:<opt1>:<opt2>   ('-' = unused)
#   kinds: vless-reality vless-grpc vless-ws vmess-tcp vmess-ws ss
# The Xray config always reflects the inbounds requested in the latest run.
. "$(dirname "$0")/lib.sh"

XDIR=/etc/xray-oneclick; ST=$XDIR/state; CFG=$XDIR/config.json; BIN=/usr/local/bin/xray
declare -a K=() P=() O1=() O2=()

# Reality SNI list: comma-separated hostnames (1-10). The first one is the handshake target.
check_snis() { # <list>
  local list="$1" n=0 s
  local -a arr=()
  IFS=, read -ra arr <<<"$list"
  for s in "${arr[@]}"; do
    [[ "$s" =~ ^[A-Za-z0-9.-]{1,253}$ ]] || die 2 "Invalid Reality SNI"
    n=$((n + 1))
  done
  (( n >= 1 && n <= 10 )) || die 2 "Reality SNI list must have 1-10 entries"
}
sni_first() { printf '%s' "${1%%,*}"; }
sni_json() { # <list> -> "a","b"
  local -a arr=(); local s out=""
  IFS=, read -ra arr <<<"$1"
  for s in "${arr[@]}"; do out="$out${out:+,}\"$s\""; done
  printf '%s' "$out"
}

parse_specs() {
  local s k p a b i j
  for s in "$@"; do
    IFS=: read -r k p a b <<<"$s"
    [[ "$k" =~ ^(vless-reality|vless-grpc|vless-ws|vmess-tcp|vmess-ws|ss)$ ]] || die 2 "Invalid inbound kind"
    [[ "$p" =~ ^[0-9]{1,5}$ ]] && (( p >= 1 && p <= 65535 )) || die 2 "Invalid inbound port"
    case "$k" in
      vless-reality) check_snis "$a" ;;
      vless-grpc) check_snis "$a"; [[ "$b" =~ ^[A-Za-z0-9_-]{1,64}$ ]] || die 2 "Invalid Reality/gRPC settings" ;;
      vless-ws|vmess-ws) [[ "$a" =~ ^/[A-Za-z0-9_/-]{0,64}$ ]] || die 2 "Invalid WebSocket path" ;;
      ss) [[ "$a" =~ ^(2022-blake3-aes-128-gcm|2022-blake3-aes-256-gcm|aes-256-gcm|chacha20-ietf-poly1305)$ ]] || die 2 "Invalid Shadowsocks method" ;;
    esac
    K+=("$k"); P+=("$p"); O1+=("${a:-}"); O2+=("${b:-}")
  done
  [ "${#K[@]}" -gt 0 ] || die 2 "No inbounds requested"
  for ((i = 0; i < ${#K[@]}; i++)); do
    for ((j = i + 1; j < ${#K[@]}; j++)); do
      [ "${P[$i]}" != "${P[$j]}" ] || die 2 "Two inbounds use the same port ${P[$i]}"
    done
  done
}

install_xray() {
  local a t base exp act
  if [ -x "$BIN" ]; then echo "Xray already installed: $("$BIN" version | head -n1)"; return; fi
  apt_install curl unzip openssl ca-certificates
  case "$(uname -m)" in x86_64|amd64) a=64 ;; aarch64|arm64) a=arm64-v8a ;; *) die 10 "Unsupported CPU architecture" ;; esac
  t="$(mktemp -d)"; base=https://github.com/XTLS/Xray-core/releases/latest/download
  curl -fsSL --retry 3 -o "$t/x.zip" "$base/Xray-linux-$a.zip" || { rm -rf "$t"; die 81 "Could not download Xray"; }
  curl -fsSL --retry 3 -o "$t/x.dgst" "$base/Xray-linux-$a.zip.dgst" || { rm -rf "$t"; die 81 "Could not download the Xray checksum"; }
  exp="$(grep -i 'SHA2-256' "$t/x.dgst" | head -n1 | awk '{print $NF}' | tr 'A-F' 'a-f' || true)"
  act="$(sha256sum "$t/x.zip" | awk '{print $1}')"
  if [ -z "$exp" ] || [ "$exp" != "$act" ]; then rm -rf "$t"; die 81 "Xray checksum verification failed"; fi
  unzip -oq "$t/x.zip" xray -d "$t"
  install -m 755 "$t/xray" "$BIN"
  rm -rf "$t"
  echo "Xray installed: $("$BIN" version | head -n1)"
}

gen_state() {
  local out priv pub
  install -d -m 700 "$XDIR" "$ST"
  [ -s "$ST/uuid" ] || cat /proc/sys/kernel/random/uuid > "$ST/uuid"
  if [ ! -s "$ST/rpriv" ]; then
    # Output labels differ between Xray versions: "Private key:"/"Public key:" (old),
    # "PrivateKey:"/"Password:" and "Password (PublicKey):" (new). Match by prefix.
    out="$("$BIN" x25519 2>&1 | tr -d '\r' || true)"
    priv="$(grep -iE '^[[:space:]]*private' <<<"$out" | head -n1 | awk '{print $NF}' || true)"
    pub="$(grep -iE '^[[:space:]]*(public|password)' <<<"$out" | head -n1 | awk '{print $NF}' || true)"
    if [ -n "$priv" ] && [ -z "$pub" ]; then
      out="$("$BIN" x25519 -i "$priv" 2>&1 | tr -d '\r' || true)"
      pub="$(grep -iE '^[[:space:]]*(public|password)' <<<"$out" | head -n1 | awk '{print $NF}' || true)"
    fi
    if ! [[ "$priv" =~ ^[A-Za-z0-9_-]{40,50}$ && "$pub" =~ ^[A-Za-z0-9_-]{40,50}$ ]]; then
      echo "x25519 output fields: $(sed 's/:.*//' <<<"$out" | tr '\n' ',')"
      die 82 "Could not generate Reality keys"
    fi
    printf '%s' "$priv" > "$ST/rpriv"; printf '%s' "$pub" > "$ST/rpub"
  fi
  [ -s "$ST/sid" ] || openssl rand -hex 8 > "$ST/sid"
}

ss_pw() { # <method>
  local f="$ST/ss-$1"
  if [ ! -s "$f" ]; then
    case "$1" in
      2022-blake3-aes-128-gcm) openssl rand -base64 16 ;;
      2022-blake3-aes-256-gcm) openssl rand -base64 32 ;;
      *) openssl rand -base64 18 ;;
    esac | tr -d '\n' > "$f"
  fi
  cat "$f"
}

inbound_json() { # <index>
  local i="$1" k="${K[$1]}" p="${P[$1]}" a="${O1[$1]}" b="${O2[$1]}" u
  u="$(cat "$ST/uuid")"
  local sniff='"sniffing":{"enabled":true,"destOverride":["http","tls","quic"]}'
  case "$k" in
    vless-reality)
      printf '{"tag":"in%s","port":%s,"protocol":"vless","settings":{"clients":[{"id":"%s","flow":"xtls-rprx-vision"}],"decryption":"none"},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"show":false,"dest":"%s:443","xver":0,"serverNames":[%s],"privateKey":"%s","shortIds":["%s"]}},%s}' \
        "$i" "$p" "$u" "$(sni_first "$a")" "$(sni_json "$a")" "$(cat "$ST/rpriv")" "$(cat "$ST/sid")" "$sniff" ;;
    vless-grpc)
      printf '{"tag":"in%s","port":%s,"protocol":"vless","settings":{"clients":[{"id":"%s"}],"decryption":"none"},"streamSettings":{"network":"grpc","security":"reality","grpcSettings":{"serviceName":"%s"},"realitySettings":{"show":false,"dest":"%s:443","xver":0,"serverNames":[%s],"privateKey":"%s","shortIds":["%s"]}},%s}' \
        "$i" "$p" "$u" "$b" "$(sni_first "$a")" "$(sni_json "$a")" "$(cat "$ST/rpriv")" "$(cat "$ST/sid")" "$sniff" ;;
    vless-ws)
      printf '{"tag":"in%s","port":%s,"protocol":"vless","settings":{"clients":[{"id":"%s"}],"decryption":"none"},"streamSettings":{"network":"ws","security":"none","wsSettings":{"path":"%s"}},%s}' \
        "$i" "$p" "$u" "$a" "$sniff" ;;
    vmess-tcp)
      printf '{"tag":"in%s","port":%s,"protocol":"vmess","settings":{"clients":[{"id":"%s","alterId":0}]},"streamSettings":{"network":"tcp","security":"none"},%s}' \
        "$i" "$p" "$u" "$sniff" ;;
    vmess-ws)
      printf '{"tag":"in%s","port":%s,"protocol":"vmess","settings":{"clients":[{"id":"%s","alterId":0}]},"streamSettings":{"network":"ws","security":"none","wsSettings":{"path":"%s"}},%s}' \
        "$i" "$p" "$u" "$a" "$sniff" ;;
    ss)
      printf '{"tag":"in%s","port":%s,"protocol":"shadowsocks","settings":{"method":"%s","password":"%s","network":"tcp,udp"}}' \
        "$i" "$p" "$a" "$(ss_pw "$a")" ;;
  esac
}

write_config() {
  local i
  {
    printf '{"log":{"loglevel":"warning"},"inbounds":['
    for i in "${!K[@]}"; do
      if [ "$i" -gt 0 ]; then printf ','; fi
      inbound_json "$i"
    done
    printf '],"outbounds":[{"protocol":"freedom","tag":"direct"},{"protocol":"blackhole","tag":"block"}]}\n'
  } > "$CFG"
}

emit_links() {
  local i k p a b u pub sid name json s tag nm
  local -a snis=()
  u="$(cat "$ST/uuid")"
  for i in "${!K[@]}"; do
    k="${K[$i]}"; p="${P[$i]}"; a="${O1[$i]}"; b="${O2[$i]}"
    name="$(urlenc "$CLIENT-$k")"
    case "$k" in
      vless-reality|vless-grpc)
        pub="$(cat "$ST/rpub")"; sid="$(cat "$ST/sid")"
        IFS=, read -ra snis <<<"$a"
        for s in "${snis[@]}"; do
          tag="$k"; nm="$name"
          if [ "${#snis[@]}" -gt 1 ]; then tag="$k@$s"; nm="$(urlenc "$CLIENT-$k-$s")"; fi
          if [ "$k" = vless-reality ]; then
            echo "##LINK $tag vless://$u@$HOSTURI:$p?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$s&fp=chrome&pbk=$pub&sid=$sid&type=tcp&headerType=none#$nm"
          else
            echo "##LINK $tag vless://$u@$HOSTURI:$p?encryption=none&security=reality&sni=$s&fp=chrome&pbk=$pub&sid=$sid&type=grpc&serviceName=$b&mode=gun#$nm"
          fi
        done ;;
      vless-ws)
        echo "##LINK $k vless://$u@$HOSTURI:$p?encryption=none&security=none&type=ws&path=$(urlenc "$a")#$name" ;;
      vmess-tcp)
        json="$(printf '{"v":"2","ps":"%s","add":"%s","port":"%s","id":"%s","aid":"0","scy":"auto","net":"tcp","type":"none","host":"","path":"","tls":""}' "$CLIENT-$k" "$ADDR" "$p" "$u")"
        echo "##LINK $k vmess://$(printf '%s' "$json" | base64 -w0)" ;;
      vmess-ws)
        json="$(printf '{"v":"2","ps":"%s","add":"%s","port":"%s","id":"%s","aid":"0","scy":"auto","net":"ws","type":"none","host":"","path":"%s","tls":""}' "$CLIENT-$k" "$ADDR" "$p" "$u" "$a")"
        echo "##LINK $k vmess://$(printf '%s' "$json" | base64 -w0)" ;;
      ss)
        if [[ "$a" == 2022-* ]]; then
          echo "##LINK $k ss://$a:$(urlenc "$(ss_pw "$a")")@$HOSTURI:$p#$name"
        else
          echo "##LINK $k ss://$(b64url "$a:$(ss_pw "$a")")@$HOSTURI:$p#$name"
        fi ;;
    esac
  done
}

main() {
  local i
  parse_specs "$@"

  step 1
  check_server
  for i in "${!K[@]}"; do
    port_check tcp "${P[$i]}" xray
    if [ "${K[$i]}" = ss ]; then port_check udp "${P[$i]}" xray; fi
    case "${K[$i]}" in
      vless-reality|vless-grpc)
        command -v curl >/dev/null || apt_install curl ca-certificates
        local first; first="$(sni_first "${O1[$i]}")"
        curl -sS -o /dev/null --max-time 10 "https://$first" 2>/dev/null \
          || die 80 "Reality target $first is not reachable from this server" ;;
    esac
  done

  step 2
  install_xray

  step 3
  gen_state
  install -d -m 750 "$XDIR"
  write_config
  chown root:nogroup "$XDIR" "$CFG"; chmod 640 "$CFG"
  "$BIN" run -test -config "$CFG" >/dev/null 2>&1 || { "$BIN" run -test -config "$CFG" 2>&1 | tail -n 6; die 83 "Generated Xray configuration was rejected"; }

  step 4
  for i in "${!K[@]}"; do
    fw_open tcp "${P[$i]}"
    if [ "${K[$i]}" = ss ]; then fw_open udp "${P[$i]}"; fi
  done
  fw_apply

  step 5
  cat > /etc/systemd/system/xray-oneclick.service <<UNIT
[Unit]
Description=Xray (one-click)
After=network-online.target
Wants=network-online.target

[Service]
User=nobody
Group=nogroup
ExecStart=$BIN run -config $CFG
Restart=on-failure
LimitNOFILE=65535
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable xray-oneclick >/dev/null 2>&1 || die 30 "Could not enable Xray"
  if ! systemctl restart xray-oneclick; then
    journalctl -u xray-oneclick -n 12 --no-pager 2>&1 | sed 's/^/  /' || true
    die 30 "Xray failed to start"
  fi
  for i in "${!K[@]}"; do
    wait_listening tcp "${P[$i]}" xray || { journalctl -u xray-oneclick -n 12 --no-pager 2>&1 | sed 's/^/  /' || true; die 31 "Xray is not listening on tcp/${P[$i]}"; }
  done
  echo "Xray is running (${#K[@]} inbound(s))"

  step 6
  emit_links
}

if [ "${ONECLICK_SOURCE_ONLY:-0}" != 1 ]; then main "$@"; fi
