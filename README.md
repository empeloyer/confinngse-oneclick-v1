# configset (Android)

Enter SSH details → pick UDP/TCP + port → tap **INSTALL & GENERATE CONFIG** → save a ready-to-import `.ovpn`.

## Config types (all work with just a server, no domain)
Turn on any combination; each has its own port and options. Scripts live in `app/src/main/assets/` (`lib.sh` + one per group) and are
uploaded over SFTP, run with validated single-quoted arguments, and report real progress via `##STEP n`.

| Type | Result | Notes |
|---|---|---|
| OpenVPN (UDP/TCP) | `.ovpn` file (save/share) | EC PKI, tls-crypt, AES-256-GCM; never modifies an OpenVPN it didn't create |
| WireGuard | `.conf` file (save/share) | adds a new peer per run; MTU configurable |
| VLESS Reality (TCP Vision / gRPC) | copyable `vless://` link | Xray; one or more SNI targets (comma-separated; first = handshake target, one link per SNI), no domain/cert needed |
| VLESS / VMess WebSocket, VMess TCP (no TLS) | copyable link | weaker, easier to detect (warned in UI) |
| Shadowsocks (2022 or AEAD) | copyable `ss://` link | method selectable |
| Hysteria2 | copyable `hysteria2://` link | self-signed cert, SHA-256 pinned in the link |
| SSH tunnel | copyable `ssh://user:pass@host:port` link | creates a tunnel-only account (no shell/TTY) on the server's existing sshd; random password if left blank; never modifies accounts the app did not create |

All Xray types share one service (`xray-oneclick`); its config always reflects the types selected in the latest run, and its UUID/keys are reused.
Xray and Hysteria2 binaries are downloaded from their official GitHub releases and verified against the published checksum.
The SSH tunnel type adds a `Match User` drop-in in `/etc/ssh/sshd_config.d/`, validated with `sshd -t` and reverted on failure; the port is the one sshd already listens on.
Not included because they need a domain/CA certificate or a client-side extra: Trojan/VLESS with real TLS, TUIC.

## Security
SSH host key is verified (trust-on-first-use with an explicit fingerprint prompt; a changed key is refused).
Saved credentials use AES-256-GCM with an Android Keystore key. Logs never show passwords, key material or profile contents.
No third-party services are contacted. The `.ovpn` contains a private key: treat it as secret.

## Build
- Android Studio (Hedgehog+), JDK 17: open the folder and run `app`.
- CLI: `gradle :app:testDebugUnitTest :app:assembleDebug` (Gradle 8.7). The wrapper JAR is not included; run `gradle wrapper` once to generate it.
- GitHub: push and run the **Build debug APK** workflow (`.github/workflows/build.yml`); the APK is uploaded as an artifact.

## Known limits
- Cloud-provider firewalls/security groups (outside the VPS) must allow the chosen port/protocol.
- Non-root users need passwordless sudo (`sudo -n`).
- If the app is killed mid-install the remote script may stop; just run again.
- OpenVZ/LXC VPSes without a TUN device cannot run OpenVPN.
