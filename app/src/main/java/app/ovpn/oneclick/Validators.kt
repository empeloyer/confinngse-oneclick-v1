package app.ovpn.oneclick

object Validators {
    private val HOST = Regex("^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
    private val IPV6 = Regex("^[0-9A-Fa-f:]{2,45}$")
    private val USER = Regex("^[a-z_][a-z0-9_-]{0,31}$")
    private val CLIENT = Regex("^[A-Za-z0-9_-]{1,40}$")
    private val PATH = Regex("^/[A-Za-z0-9_/-]{0,64}$")
    private val SERVICE = Regex("^[A-Za-z0-9_-]{1,64}$")

    private const val MAX_SNI = 10
    private val SNI = Regex("^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")

    /** Splits "a.com, b.com\nc.com" into a distinct, trimmed list (order kept; the first is the handshake target). */
    fun parseSnis(s: String): List<String> =
        s.split(',', ';', '\n', ' ').map { it.trim().lowercase() }.filter { it.isNotEmpty() }.distinct()

    fun snisError(s: String): String? {
        val l = parseSnis(s)
        return when {
            l.isEmpty() -> "Enter at least one Reality SNI target."
            l.size > MAX_SNI -> "At most $MAX_SNI SNI targets."
            l.any { it.length > 253 || !SNI.matches(it) } -> "Reality SNI target is invalid."
            else -> null
        }
    }

    private val RESERVED_USERS = setOf(
        "root", "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail", "news", "uucp", "proxy",
        "www-data", "backup", "list", "irc", "nobody", "sshd", "ubuntu", "debian", "admin"
    )
    private val TUNNEL_PASSWORD = Regex("^[A-Za-z0-9._-]{8,64}$")

    /** Blank means "generate a random password on the server". */
    fun isTunnelPassword(s: String) = s.isEmpty() || TUNNEL_PASSWORD.matches(s)

    fun isHost(s: String) = s.length <= 253 && (HOST.matches(s) || (s.contains(':') && IPV6.matches(s)))
    fun isUser(s: String) = USER.matches(s)
    fun isPort(s: String) = s.toIntOrNull()?.let { it in 1..65535 } ?: false
    fun isClientName(s: String) = CLIENT.matches(s)

    private fun kindError(k: Kind, s: ProtoSetting): String? = when (k) {
        Kind.WIREGUARD -> if (s.opt1.toIntOrNull()?.let { it in 1280..1500 } == true) null else "WireGuard MTU must be 1280-1500."
        Kind.VLESS_REALITY -> snisError(s.opt1)
        Kind.VLESS_GRPC ->
            if (snisError(s.opt1) != null) snisError(s.opt1)
            else if (!SERVICE.matches(s.opt2.trim())) "gRPC service name is invalid (letters, digits, - _)."
            else null
        Kind.VLESS_WS, Kind.VMESS_WS -> if (PATH.matches(s.opt1.trim())) null else "${k.label}: path must start with / (letters, digits, - _ /)."
        Kind.SHADOWSOCKS -> if (s.opt1 in SS_METHODS) null else "Choose a Shadowsocks method."
        Kind.SSH -> when {
            !isUser(s.opt1.trim()) || s.opt1.trim() in RESERVED_USERS -> "SSH tunnel username is invalid or reserved (lowercase letters, digits, - _)."
            !isTunnelPassword(s.opt2) -> "SSH tunnel password must be 8-64 characters (letters, digits, . _ -) or blank for a random one."
            else -> null
        }
        else -> null
    }

    /** Returns an error message, or null when the form is valid. */
    fun validate(f: ConnectionForm): String? {
        when {
            !isHost(f.host.trim()) -> return "Enter a valid VPS IP address or hostname."
            !isPort(f.sshPort.trim()) -> return "SSH port must be 1-65535."
            !isUser(f.user.trim()) -> return "SSH username contains unsupported characters."
            f.auth == AuthMethod.PASSWORD && f.password.isEmpty() -> return "Enter the SSH password."
            f.auth == AuthMethod.KEY && !f.privateKey.contains("PRIVATE KEY") -> return "Paste or import a valid private key."
            f.serverAddress.isNotBlank() && !isHost(f.serverAddress.trim()) -> return "Server address override is invalid."
        }
        val kinds = f.enabledKinds()
        if (kinds.isEmpty()) return "Turn on at least one config type."
        val seen = HashSet<String>()
        for (k in kinds) {
            val s = f.setting(k)
            if (!isPort(s.port.trim())) return "${k.label}: port must be 1-65535."
            val tr = f.transportOf(k)
            if (!seen.add("$tr/${s.port.trim()}")) return "Two configs use the same $tr port ${s.port.trim()}."
            if (k != Kind.SSH && tr == "tcp" && s.port.trim() == f.sshPort.trim()) return "${k.label}: port ${s.port.trim()} is your SSH port."
            kindError(k, s)?.let { return it }
            if (k == Kind.SSH && s.opt1.trim() == f.user.trim()) return "${k.label}: the tunnel username must differ from your SSH login user."
        }
        return null
    }

    fun looksLikeOvpn(text: String): Boolean =
        text.length in 500..200_000 &&
            text.contains("\nremote ") &&
            listOf("<ca>", "</ca>", "<cert>", "</cert>", "<key>", "</key>").all { text.contains(it) } &&
            text.contains("PRIVATE KEY")

    fun looksLikeWireGuard(text: String): Boolean =
        text.length in 150..20_000 && listOf("[Interface]", "PrivateKey", "[Peer]", "PublicKey", "Endpoint").all { text.contains(it) }

    fun looksLikeLink(url: String): Boolean =
        url.length in 20..4000 && Regex("^(vless|vmess|ss|ssh|hysteria2)://[^\\s]+$").matches(url)
}

object LogSanitizer {
    /** Returns null for lines that must never be shown (key material, blanks, huge lines, share links). */
    fun clean(line: String, secrets: List<String>): String? {
        var s = line.trimEnd()
        if (s.isBlank() || s.startsWith("-----") || s.contains("PRIVATE KEY") || s.length > 300) return null
        if (Regex("(vless|vmess|ss|ssh|hysteria2)://").containsMatchIn(s)) return null
        for (x in secrets) if (x.length >= 3) s = s.replace(x, "***")
        return s
    }
}
