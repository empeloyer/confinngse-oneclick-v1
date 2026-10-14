package app.ovpn.oneclick

import org.json.JSONObject

enum class Proto(val value: String) { UDP("udp"), TCP("tcp") }

enum class DnsChoice(val label: String, val primary: String, val secondary: String) {
    CLOUDFLARE("Cloudflare", "1.1.1.1", "1.0.0.1"),
    GOOGLE("Google", "8.8.8.8", "8.8.4.4"),
    QUAD9("Quad9", "9.9.9.9", "149.112.112.112")
}

enum class AuthMethod { PASSWORD, KEY }

/** One server-side script per group; Xray covers VLESS/VMess/Shadowsocks in a single install. */
enum class Group(val label: String, val script: String, val steps: List<String>) {
    OPENVPN("OpenVPN", "openvpn.sh", listOf(
        "Checking server", "Installing OpenVPN", "Generating certificates", "Configuring network and firewall",
        "Starting OpenVPN", "Generating client certificate", "Building client configuration")),
    WIREGUARD("WireGuard", "wireguard.sh", listOf(
        "Checking server", "Installing WireGuard", "Generating keys", "Configuring network and firewall",
        "Starting WireGuard", "Building client configuration")),
    XRAY("Xray", "xray.sh", listOf(
        "Checking server", "Installing Xray", "Generating credentials", "Opening firewall",
        "Starting Xray", "Building client links")),
    HYSTERIA2("Hysteria2", "hysteria2.sh", listOf(
        "Checking server", "Installing Hysteria2", "Generating certificate", "Opening firewall",
        "Starting Hysteria2", "Building client link")),
    SSH("SSH", "ssh.sh", listOf(
        "Checking server", "Creating tunnel user", "Restricting account to tunneling",
        "Reloading SSH", "Building client link"))
}

val SS_METHODS = listOf("2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "aes-256-gcm", "chacha20-ietf-poly1305")

/** Every config type that needs only a server (no domain, no CA-issued certificate). */
enum class Kind(
    val id: String,
    val label: String,
    val group: Group,
    val defaultPort: String,
    val transport: String?, // null = chosen by the user (OpenVPN)
    val opt1Label: String? = null,
    val opt1Default: String = "",
    val opt2Label: String? = null,
    val opt2Default: String = "",
    val warning: String? = null,
    val hint: String? = null
) {
    OPENVPN("openvpn", "OpenVPN (.ovpn file)", Group.OPENVPN, "1194", null),
    WIREGUARD("wireguard", "WireGuard (.conf file)", Group.WIREGUARD, "51820", "udp", "MTU (1280-1500)", "1380"),
    VLESS_REALITY("vless-reality", "VLESS · Reality (TCP, Vision)", Group.XRAY, "443", "tcp", "Reality SNI targets (comma-separated)", "www.microsoft.com"),
    VLESS_GRPC("vless-grpc", "VLESS · Reality (gRPC)", Group.XRAY, "8443", "tcp", "Reality SNI targets (comma-separated)", "www.microsoft.com", "gRPC service name", "grpc"),
    VLESS_WS("vless-ws", "VLESS · WebSocket (no TLS)", Group.XRAY, "8080", "tcp", "WebSocket path", "/vless",
        warning = "No transport encryption and easier to detect. Prefer Reality."),
    VMESS_TCP("vmess-tcp", "VMess · TCP (no TLS)", Group.XRAY, "8880", "tcp",
        warning = "No transport encryption and easier to detect. Prefer Reality."),
    VMESS_WS("vmess-ws", "VMess · WebSocket (no TLS)", Group.XRAY, "8881", "tcp", "WebSocket path", "/vmess",
        warning = "No transport encryption and easier to detect. Prefer Reality."),
    SHADOWSOCKS("ss", "Shadowsocks", Group.XRAY, "8388", "tcp", "Method", "2022-blake3-aes-128-gcm"),
    HYSTERIA2("hysteria2", "Hysteria2 (self-signed, pinned)", Group.HYSTERIA2, "443", "udp"),
    SSH("ssh", "SSH tunnel (ssh:// link)", Group.SSH, "22", "tcp", "Tunnel username", "sshtunnel", "Password (blank = random)",
        hint = "Creates a tunnel-only account (no shell) on the server's existing SSH service. " +
            "The port is the one your SSH server listens on for clients.");

    /** True for kinds whose first option is a (multi-)SNI list. */
    val multiSni: Boolean get() = this == VLESS_REALITY || this == VLESS_GRPC

    companion object {
        fun byId(id: String) = values().firstOrNull { it.id == id }
    }
}

data class ProtoSetting(
    val enabled: Boolean = false,
    val port: String = "",
    val opt1: String = "",
    val opt2: String = ""
)

fun defaultProtos(): Map<Kind, ProtoSetting> = Kind.values().associateWith {
    ProtoSetting(enabled = it == Kind.OPENVPN, port = it.defaultPort, opt1 = it.opt1Default, opt2 = it.opt2Default)
}

data class ConnectionForm(
    val host: String = "",
    val sshPort: String = "22",
    val user: String = "root",
    val auth: AuthMethod = AuthMethod.PASSWORD,
    val password: String = "",
    val privateKey: String = "",
    val passphrase: String = "",
    val proto: Proto = Proto.UDP,          // OpenVPN transport
    val dns: DnsChoice = DnsChoice.CLOUDFLARE, // OpenVPN + WireGuard
    val serverAddress: String = "",
    val protos: Map<Kind, ProtoSetting> = defaultProtos()
) {
    fun setting(k: Kind): ProtoSetting = protos[k] ?: ProtoSetting(port = k.defaultPort, opt1 = k.opt1Default, opt2 = k.opt2Default)
    fun enabledKinds(): List<Kind> = Kind.values().filter { setting(it).enabled }
    fun transportOf(k: Kind): String = k.transport ?: proto.value

    fun toJson(): String = JSONObject().apply {
        put("host", host); put("sshPort", sshPort); put("user", user)
        put("auth", auth.name); put("password", password); put("privateKey", privateKey)
        put("passphrase", passphrase); put("proto", proto.name); put("dns", dns.name)
        put("serverAddress", serverAddress)
        put("protos", JSONObject().apply {
            Kind.values().forEach { k ->
                val s = setting(k)
                put(k.name, JSONObject().put("enabled", s.enabled).put("port", s.port).put("opt1", s.opt1).put("opt2", s.opt2))
            }
        })
    }.toString()

    companion object {
        fun fromJson(s: String): ConnectionForm? = try {
            val o = JSONObject(s)
            val po = o.optJSONObject("protos")
            val protos = Kind.values().associateWith { k ->
                val d = po?.optJSONObject(k.name)
                if (d == null) defaultProtos().getValue(k) else ProtoSetting(
                    d.optBoolean("enabled", k == Kind.OPENVPN), d.optString("port", k.defaultPort),
                    d.optString("opt1", k.opt1Default), d.optString("opt2", k.opt2Default)
                )
            }
            ConnectionForm(
                host = o.optString("host"), sshPort = o.optString("sshPort", "22"),
                user = o.optString("user", "root"),
                auth = AuthMethod.valueOf(o.optString("auth", "PASSWORD")),
                password = o.optString("password"), privateKey = o.optString("privateKey"),
                passphrase = o.optString("passphrase"),
                proto = Proto.valueOf(o.optString("proto", "UDP")),
                dns = DnsChoice.valueOf(o.optString("dns", "CLOUDFLARE")),
                serverAddress = o.optString("serverAddress"), protos = protos
            )
        } catch (e: Exception) { null }
    }
}

/** Real progress plan: connect, each selected group's server steps, then download. */
data class Plan(val groups: List<Group>, val labels: List<String>) {
    fun offset(g: Group): Int = 1 + groups.takeWhile { it != g }.sumOf { it.steps.size }
    val downloadIndex: Int get() = labels.lastIndex
}

fun buildPlan(f: ConnectionForm): Plan {
    val enabled = f.enabledKinds().map { it.group }.toSet()
    val groups = Group.values().filter { it in enabled }
    val labels = listOf("Connecting to VPS") +
        groups.flatMap { g -> g.steps.map { "${g.label}: $it" } } +
        "Downloading configuration"
    return Plan(groups, labels)
}

sealed interface ResultItem { val title: String }
class FileResult(override val title: String, val fileName: String, val bytes: ByteArray) : ResultItem
class LinkResult(override val title: String, val link: String) : ResultItem
class FailedResult(override val title: String, val message: String, val recovery: String) : ResultItem
