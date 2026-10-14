package app.ovpn.oneclick

import com.jcraft.jsch.ChannelExec
import com.jcraft.jsch.ChannelSftp
import com.jcraft.jsch.HostKey
import com.jcraft.jsch.HostKeyRepository
import com.jcraft.jsch.JSch
import com.jcraft.jsch.JSchException
import com.jcraft.jsch.Session
import com.jcraft.jsch.UserInfo
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import java.io.ByteArrayInputStream
import java.security.MessageDigest
import java.security.SecureRandom
import android.util.Base64

class InstallException(val code: Int, message: String) : Exception(message)

class SshInstaller(
    private val known: KnownHosts,
    private val assets: Map<String, String>, // script file name -> text (lib.sh + one per group)
    private val confirmHostKey: suspend (hostId: String, fingerprint: String) -> Boolean
) {
    interface Listener {
        fun onStep(index: Int)
        fun onLog(line: String)
    }

    private class GroupOutput(val files: List<Pair<String, String>>, val links: List<Pair<String, String>>)

    fun hostId(f: ConnectionForm) = "${f.host.trim()}:${f.sshPort.trim()}"

    private fun argsFor(g: Group, f: ConnectionForm): String = when (g) {
        Group.OPENVPN -> "'${f.proto.value}' '${f.setting(Kind.OPENVPN).port.trim()}'"
        Group.WIREGUARD -> "'${f.setting(Kind.WIREGUARD).port.trim()}' '${f.setting(Kind.WIREGUARD).opt1.trim()}'"
        Group.HYSTERIA2 -> "'${f.setting(Kind.HYSTERIA2).port.trim()}'"
        Group.SSH -> f.setting(Kind.SSH).let { st -> "'${st.port.trim()}' '${st.opt1.trim()}' '${st.opt2.ifEmpty { "-" }}'" }
        Group.XRAY -> f.enabledKinds().filter { it.group == Group.XRAY }.joinToString(" ") { k ->
            val st = f.setting(k)
            val o1 = if (k.multiSni) Validators.parseSnis(st.opt1).joinToString(",") else st.opt1.trim()
            "'${k.id}:${st.port.trim()}:${o1.ifEmpty { "-" }}:${st.opt2.trim().ifEmpty { "-" }}'"
        }
    }

    suspend fun run(f: ConnectionForm, clientName: String, plan: Plan, l: Listener): List<ResultItem> =
        withContext(Dispatchers.IO) {
            val secrets = listOf(f.password, f.passphrase, f.setting(Kind.SSH).opt2)
            var session: Session? = null
            var remoteDir: String? = null
            try {
                l.onStep(0)
                session = connect(f)
                l.onLog("SSH connected, host key verified")

                val home = exec(session, "printf '%s' \"\$HOME\"").second.trim()
                val uid = exec(session, "id -u").second.trim()
                val outDir = "$home/ovpn-clients"
                if (!Regex("^/[A-Za-z0-9_./-]+$").matches(outDir)) {
                    throw InstallException(2, "Unsupported home directory path on the server: $home")
                }

                remoteDir = "/tmp/ovpn-oneclick-" + randomHex(8)
                val up = session.openChannel("sftp") as ChannelSftp
                up.connect(10_000)
                up.mkdir(remoteDir)
                up.chmod(448, remoteDir) // 0700
                for (name in listOf("lib.sh") + plan.groups.map { it.script }) {
                    val text = assets[name] ?: throw InstallException(1, "Missing bundled script $name")
                    up.put(ByteArrayInputStream(text.toByteArray()), "$remoteDir/$name")
                }
                up.disconnect()

                val addr = f.serverAddress.trim().ifEmpty { f.host.trim() }
                val sudo = if (uid == "0") "" else "sudo -n "
                val envPrefix = "${sudo}env ADDR='$addr' CLIENT='$clientName' OUT_DIR='$outDir' " +
                    "DNS1='${f.dns.primary}' DNS2='${f.dns.secondary}'"

                val results = mutableListOf<ResultItem>()
                val remoteFiles = mutableListOf<Pair<String, String>>() // kind id -> path
                for (g in plan.groups) {
                    try {
                        val out = runGroup(session, "$envPrefix bash '$remoteDir/${g.script}' ${argsFor(g, f)} 2>&1", g, plan, secrets, l)
                        remoteFiles += out.files
                        for ((id, url) in out.links) {
                            if (!Validators.looksLikeLink(url)) throw InstallException(1, "Server returned a malformed link for $id")
                            // multi-SNI links come as "<kind>@<sni>"
                            val base = id.substringBefore('@')
                            val sni = id.substringAfter('@', "")
                            val label = Kind.byId(base)?.label ?: base
                            results += LinkResult(if (sni.isEmpty()) label else "$label · $sni", url)
                        }
                    } catch (e: InstallException) {
                        val (m, r) = describe(e)
                        l.onLog("${g.label} failed: $m")
                        results += FailedResult(g.label, m, r)
                    }
                }

                if (remoteFiles.isNotEmpty()) {
                    l.onStep(plan.downloadIndex)
                    val dl = session.openChannel("sftp") as ChannelSftp
                    dl.connect(10_000)
                    for ((id, path) in remoteFiles) {
                        if (!path.startsWith("$outDir/")) throw InstallException(1, "Unexpected file path returned by server")
                        val bytes = dl.get(path).use { it.readBytes() }
                        val text = bytes.toString(Charsets.UTF_8)
                        val ok = if (id == "openvpn") Validators.looksLikeOvpn(text) else Validators.looksLikeWireGuard(text)
                        val title = Kind.byId(id)?.label ?: id
                        results += if (ok) FileResult(title, path.substringAfterLast('/'), bytes)
                        else FailedResult(title, "Downloaded file failed validation", "Run the installer again.")
                        l.onLog("$title downloaded (${bytes.size} bytes)")
                    }
                    dl.disconnect()
                }
                results
            } finally {
                try { if (session?.isConnected == true && remoteDir != null) exec(session, "rm -rf '$remoteDir'") } catch (_: Exception) {}
                try { session?.disconnect() } catch (_: Exception) {}
            }
        }

    private suspend fun runGroup(
        session: Session, cmd: String, g: Group, plan: Plan, secrets: List<String>, l: Listener
    ): GroupOutput {
        val ch = session.openChannel("exec") as ChannelExec
        ch.setCommand(cmd)
        val reader = ch.inputStream.bufferedReader()
        ch.connect(10_000)
        val files = mutableListOf<Pair<String, String>>()
        val links = mutableListOf<Pair<String, String>>()
        var lastErr: String? = null
        val tail = ArrayDeque<String>()
        while (true) {
            currentCoroutineContext().ensureActive()
            val line = reader.readLine() ?: break
            when {
                line.startsWith("##STEP ") -> line.removePrefix("##STEP ").trim().toIntOrNull()?.let {
                    l.onStep(plan.offset(g) + it.coerceIn(1, g.steps.size) - 1)
                }
                line.startsWith("##FILE ") -> line.removePrefix("##FILE ").trim().split(" ", limit = 2)
                    .takeIf { it.size == 2 }?.let { files += it[0] to it[1] }
                line.startsWith("##LINK ") -> line.removePrefix("##LINK ").trim().split(" ", limit = 2)
                    .takeIf { it.size == 2 }?.let { links += it[0] to it[1] }   // never logged
                line.startsWith("##ERR ") -> lastErr = line.removePrefix("##ERR ").trim()
                else -> LogSanitizer.clean(line, secrets)?.let {
                    l.onLog(it); tail.addLast(it); if (tail.size > 3) tail.removeFirst()
                }
            }
        }
        var waited = 0
        while (!ch.isClosed && waited < 100) { Thread.sleep(50); waited++ }
        val exit = ch.exitStatus
        ch.disconnect()
        if (exit != 0) throw InstallException(exit, lastErr ?: tail.lastOrNull() ?: "Server script failed (exit $exit)")
        if (files.isEmpty() && links.isEmpty()) throw InstallException(1, "The server script finished without producing a config")
        return GroupOutput(files, links)
    }

    private fun connect(f: ConnectionForm): Session {
        val jsch = JSch()
        if (f.auth == AuthMethod.KEY) {
            val key = (f.privateKey.trim().replace("\r\n", "\n") + "\n").toByteArray()
            jsch.addIdentity("user-key", key, null, f.passphrase.takeIf { it.isNotEmpty() }?.toByteArray())
        }
        val id = hostId(f)
        jsch.hostKeyRepository = object : HostKeyRepository {
            override fun check(host: String?, key: ByteArray?): Int {
                val fp = fingerprint(key ?: return HostKeyRepository.NOT_INCLUDED)
                val stored = known.get(id)
                return when {
                    stored == fp -> HostKeyRepository.OK
                    stored != null -> HostKeyRepository.CHANGED
                    else -> {
                        val ok = runBlocking { confirmHostKey(id, fp) }
                        if (ok) { known.put(id, fp); HostKeyRepository.OK } else HostKeyRepository.NOT_INCLUDED
                    }
                }
            }
            override fun add(hostkey: HostKey?, ui: UserInfo?) {}
            override fun remove(host: String?, type: String?) {}
            override fun remove(host: String?, type: String?, key: ByteArray?) {}
            override fun getKnownHostsRepositoryID(): String = "oneclick"
            override fun getHostKey(): Array<HostKey> = emptyArray()
            override fun getHostKey(host: String?, type: String?): Array<HostKey> = emptyArray()
        }
        val s = jsch.getSession(f.user.trim(), f.host.trim(), f.sshPort.trim().toInt())
        s.setConfig("StrictHostKeyChecking", "yes")
        if (f.auth == AuthMethod.PASSWORD) {
            s.setPassword(f.password)
            s.setConfig("PreferredAuthentications", "password,keyboard-interactive")
        } else {
            s.setConfig("PreferredAuthentications", "publickey")
        }
        s.setServerAliveInterval(15_000)
        s.connect(20_000)
        return s
    }

    private fun exec(session: Session, cmd: String): Pair<Int, String> {
        val ch = session.openChannel("exec") as ChannelExec
        ch.setCommand(cmd)
        val ins = ch.inputStream
        ch.connect(10_000)
        val out = ins.readBytes().toString(Charsets.UTF_8)
        var waited = 0
        while (!ch.isClosed && waited < 100) { Thread.sleep(50); waited++ }
        val code = ch.exitStatus
        ch.disconnect()
        return code to out
    }

    private fun randomHex(bytes: Int): String {
        val b = ByteArray(bytes); SecureRandom().nextBytes(b)
        return b.joinToString("") { "%02x".format(it) }
    }

    companion object {
        fun fingerprint(blob: ByteArray): String =
            "SHA256:" + Base64.encodeToString(MessageDigest.getInstance("SHA-256").digest(blob), Base64.NO_PADDING or Base64.NO_WRAP)

        /** Maps exceptions to (message, recovery action). */
        fun describe(e: Throwable): Pair<String, String> {
            if (e is InstallException) return e.message.orEmpty() to when (e.code) {
                10 -> "Use a VPS running Ubuntu or Debian."
                11 -> "Log in as root, or as a user with passwordless sudo."
                20 -> "An existing OpenVPN setup was found and left untouched. Use a clean VPS, or remove it manually if you are sure."
                21 -> "Choose a different OpenVPN port, or stop the service that uses it."
                22 -> "Choose another tunnel username; accounts the app did not create are never modified."
                23 -> "Enter the port your SSH server actually listens on (usually the SSH port above)."
                24 -> "The SSH server rejected the tunnel settings and nothing was changed. Check the log above."
                30, 31 -> "Check the log above. Some VPS types (OpenVZ/LXC) need the TUN device enabled by the provider."
                80 -> "Pick another Reality SNI target (a large site that supports TLS 1.3 and HTTP/2)."
                81 -> "A download or its checksum check failed. Check that the VPS can reach github.com, then retry."
                40 -> "Package installation failed. Check that the VPS has internet access and no other apt process is stuck, then retry."
                else -> "Fix the problem shown above and tap the button again; the installer is safe to re-run."
            }
            val m = e.message.orEmpty()
            return when {
                m.contains("HostKey has been changed", true) ->
                    "The SSH host key changed since you last trusted this server." to
                        "If you reinstalled the VPS, forget the saved host key and retry. Otherwise someone may be intercepting the connection."
                m.contains("UnknownHostKey", true) -> "The SSH host key was not trusted." to "Retry and confirm the fingerprint if it matches your server."
                m.contains("Auth fail", true) || m.contains("Auth cancel", true) ->
                    "SSH authentication failed." to "Check username, password, or key and passphrase."
                m.contains("invalid privatekey", true) || m.contains("passphrase", true) ->
                    "The private key could not be read." to "Check the key format and passphrase."
                e is JSchException -> ("SSH error: " + m) to "Check the address, SSH port and that the VPS is reachable."
                else -> (m.ifEmpty { e.javaClass.simpleName }) to "Retry. The installer is safe to re-run."
            }
        }
    }
}
