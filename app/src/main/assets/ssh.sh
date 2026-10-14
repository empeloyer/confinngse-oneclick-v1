#!/usr/bin/env bash
# Args: PORT USER PASS   (PASS "-" = generate a random one)
# Creates a tunnel-only SSH account (no shell, no TTY) on the server's existing sshd and prints an ssh:// link.
# Never touches an account it did not create itself.
. "$(dirname "$0")/lib.sh"
PORT="${1:-}"; SUSER="${2:-}"; SPASS="${3:--}"
[[ "$PORT" =~ ^[0-9]{1,5}$ ]] && (( PORT >= 1 && PORT <= 65535 )) || die 2 "Invalid port"
[[ "$SUSER" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || die 2 "Invalid username"
case "$SUSER" in
  root|daemon|bin|sys|sync|games|man|lp|mail|news|uucp|proxy|www-data|backup|list|irc|nobody|sshd|ubuntu|debian|admin)
    die 2 "Reserved username: $SUSER" ;;
esac
if [ "$SPASS" != "-" ]; then
  [[ "$SPASS" =~ ^[A-Za-z0-9._-]{8,64}$ ]] || die 2 "Invalid password (8-64 characters: letters, digits, . _ -)"
fi
SD=/etc/ssh/sshd_config.d; DROPIN="$SD/oneclick-ssh-$SUSER.conf"; REG="$FW_DIR/ssh-users"

step 1
check_server
command -v openssl >/dev/null 2>&1 || apt_install openssl
if ! command -v sshd >/dev/null 2>&1 && [ ! -x /usr/sbin/sshd ]; then apt_install openssh-server; fi
SSHD="$(command -v sshd 2>/dev/null || echo /usr/sbin/sshd)"
# sshd may be socket-activated (Ubuntu 22.10+), so accept any listener on the port.
LISTENING=0
for _ in $(seq 1 15); do
  if [ -n "$(ss -Hlnt "sport = :$PORT" 2>/dev/null || true)" ]; then LISTENING=1; break; fi
  sleep 1
done
[ "$LISTENING" -eq 1 ] || die 23 "Nothing is listening on tcp/$PORT (enter the port your SSH server uses)"

step 2
install -d -m 755 "$FW_DIR"; touch "$REG"
NOLOGIN="$(command -v nologin 2>/dev/null || echo /usr/sbin/nologin)"
if getent passwd "$SUSER" >/dev/null; then
  grep -qxF "$SUSER" "$REG" || die 22 "User $SUSER already exists and was not created by this app"
  echo "Updating existing tunnel user $SUSER"
else
  useradd -M -s "$NOLOGIN" "$SUSER" || die 22 "Could not create user $SUSER"
  echo "$SUSER" >> "$REG"
  echo "Created tunnel user $SUSER"
fi
if [ "$SPASS" = "-" ]; then
  SPASS="$(openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | cut -c1-20)"
  [ "${#SPASS}" -ge 16 ] || die 50 "Password generation failed"
fi
echo "$SUSER:$SPASS" | chpasswd || die 22 "Could not set the password"

step 3
install -d -m 755 "$SD"
if ! grep -qE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/' /etc/ssh/sshd_config; then
  cp -n /etc/ssh/sshd_config /etc/ssh/sshd_config.oneclick.bak || true
  sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' /etc/ssh/sshd_config
fi
cat > "$DROPIN" <<SSHCONF
Match User $SUSER
    PasswordAuthentication yes
    AllowTcpForwarding yes
    PermitTTY no
    X11Forwarding no
    AllowAgentForwarding no
    PermitTunnel no
    ForceCommand $NOLOGIN
SSHCONF
chmod 644 "$DROPIN"
install -d -m 755 /run/sshd
if ! OUT="$("$SSHD" -t 2>&1)"; then
  echo "$OUT" | tail -n 5
  rm -f "$DROPIN"
  die 24 "SSH configuration check failed; the change was reverted"
fi
EFF="$("$SSHD" -T -C "user=$SUSER,host=localhost,addr=127.0.0.1" 2>/dev/null || true)"
if [ -n "$EFF" ]; then
  grep -qi '^passwordauthentication yes' <<<"$EFF" || die 24 "The SSH server would still refuse password login for $SUSER"
  if grep -qiE '^(allowusers|allowgroups) ' <<<"$EFF"; then
    echo "Warning: sshd has AllowUsers/AllowGroups set; add $SUSER there if login is refused"
  fi
fi

step 4
systemctl reload ssh >/dev/null 2>&1 || systemctl reload sshd >/dev/null 2>&1 || true
echo "SSH server configuration reloaded"

step 5
echo "Tunnel user: $SUSER (port $PORT)"
echo "##LINK ssh ssh://$(urlenc "$SUSER"):$(urlenc "$SPASS")@$HOSTURI:$PORT#$(urlenc "$CLIENT-ssh")"
