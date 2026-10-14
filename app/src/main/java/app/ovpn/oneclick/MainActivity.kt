package app.ovpn.oneclick

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.PersistableBundle
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.FileProvider
import java.io.File

class MainActivity : ComponentActivity() {
    private val vm: MainViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme(colorScheme = darkColorScheme()) {
                Surface(Modifier.fillMaxSize()) { App(vm) }
            }
        }
    }
}

@Composable
fun App(vm: MainViewModel) {
    val s by vm.state.collectAsState()
    when (s.screen) {
        Screen.FORM -> FormScreen(vm, s)
        Screen.RUNNING -> ProgressScreen(s)
        Screen.SUCCESS -> SuccessScreen(vm, s)
        Screen.FAILURE -> FailureScreen(vm, s)
    }
    s.hostPrompt?.let { p ->
        AlertDialog(
            onDismissRequest = { vm.answerHostKey(false) },
            title = { Text("Trust this server?") },
            text = {
                Column {
                    Text("First connection to ${p.hostId}. Verify this SSH host key fingerprint with your VPS provider:")
                    Spacer(Modifier.height(8.dp))
                    Text(p.fingerprint, fontFamily = FontFamily.Monospace, fontSize = 12.sp)
                }
            },
            confirmButton = { TextButton({ vm.answerHostKey(true) }) { Text("Trust and continue") } },
            dismissButton = { TextButton({ vm.answerHostKey(false) }) { Text("Cancel") } }
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun <T> Choice(options: List<T>, selected: T, label: (T) -> String, onSelect: (T) -> Unit) {
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        options.forEach { o ->
            FilterChip(selected = o == selected, onClick = { onSelect(o) }, label = { Text(label(o)) })
        }
    }
}

@Composable
fun FormScreen(vm: MainViewModel, s: UiState) {
    val ctx = LocalContext.current
    val f = s.form
    val pickKey = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        uri?.let {
            ctx.contentResolver.openInputStream(it)?.use { st ->
                val text = st.readBytes().decodeToString().take(20_000)
                vm.update { old -> old.copy(privateKey = text) }
            }
        }
    }
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).statusBarsPadding().navigationBarsPadding().imePadding().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        Text("configset", style = MaterialTheme.typography.headlineSmall)
        Text("VPS SSH details", style = MaterialTheme.typography.titleMedium)
        OutlinedTextField(f.host, { v -> vm.update { it.copy(host = v) } }, label = { Text("VPS IP or hostname") }, singleLine = true, modifier = Modifier.fillMaxWidth())
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedTextField(f.sshPort, { v -> vm.update { it.copy(sshPort = v) } }, label = { Text("SSH port") }, singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number), modifier = Modifier.weight(1f))
            OutlinedTextField(f.user, { v -> vm.update { it.copy(user = v) } }, label = { Text("Username") }, singleLine = true, modifier = Modifier.weight(1f))
        }
        Choice(AuthMethod.values().toList(), f.auth, { if (it == AuthMethod.PASSWORD) "Password" else "Private key" }) { a -> vm.update { it.copy(auth = a) } }
        if (f.auth == AuthMethod.PASSWORD) {
            OutlinedTextField(f.password, { v -> vm.update { it.copy(password = v) } }, label = { Text("SSH password") }, singleLine = true,
                visualTransformation = PasswordVisualTransformation(), modifier = Modifier.fillMaxWidth())
        } else {
            OutlinedTextField(f.privateKey, { v -> vm.update { it.copy(privateKey = v) } }, label = { Text("Private key (PEM/OpenSSH)") },
                minLines = 3, maxLines = 5, visualTransformation = PasswordVisualTransformation(), modifier = Modifier.fillMaxWidth())
            OutlinedButton({ pickKey.launch(arrayOf("*/*")) }) { Text("Import key file") }
            OutlinedTextField(f.passphrase, { v -> vm.update { it.copy(passphrase = v) } }, label = { Text("Key passphrase (optional)") }, singleLine = true,
                visualTransformation = PasswordVisualTransformation(), modifier = Modifier.fillMaxWidth())
        }

        Text("Config types (server-only, no domain needed)", style = MaterialTheme.typography.titleMedium)
        Kind.values().forEach { k -> KindCard(vm, f, k) }
        if (f.enabledKinds().any { it == Kind.OPENVPN || it == Kind.WIREGUARD }) {
            Text("DNS for OpenVPN / WireGuard")
            Choice(DnsChoice.values().toList(), f.dns, { it.label }) { d -> vm.update { it.copy(dns = d) } }
        }
        OutlinedTextField(f.serverAddress, { v -> vm.update { it.copy(serverAddress = v) } }, label = { Text("Server address in configs (blank = VPS host)") },
            singleLine = true, modifier = Modifier.fillMaxWidth())

        Row {
            Checkbox(s.saveCredentials, { vm.setSave(it) })
            Text("Save connection details (Keystore-encrypted)", Modifier.align(androidx.compose.ui.Alignment.CenterVertically))
        }
        s.formError?.let { Text(it, color = MaterialTheme.colorScheme.error) }
        Button({ vm.start() }, Modifier.fillMaxWidth().height(56.dp)) { Text("INSTALL & GENERATE CONFIG") }
    }
}

@Composable
fun KindCard(vm: MainViewModel, f: ConnectionForm, k: Kind) {
    val st = f.setting(k)
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                Text(k.label, Modifier.weight(1f))
                Switch(st.enabled, { v -> vm.updateKind(k) { it.copy(enabled = v) } })
            }
            if (st.enabled) {
                if (k == Kind.OPENVPN) Choice(Proto.values().toList(), f.proto, { it.name }) { p -> vm.update { it.copy(proto = p) } }
                OutlinedTextField(st.port, { v -> vm.updateKind(k) { it.copy(port = v) } },
                    label = { Text(if (k == Kind.SSH) "SSH server port (TCP)" else "Port (${f.transportOf(k).uppercase()})") }, singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number), modifier = Modifier.fillMaxWidth())
                if (k == Kind.SHADOWSOCKS) {
                    SS_METHODS.forEach { m ->
                        FilterChip(selected = st.opt1 == m, onClick = { vm.updateKind(k) { it.copy(opt1 = m) } }, label = { Text(m) })
                    }
                } else {
                    k.opt1Label?.let { lbl ->
                        OutlinedTextField(st.opt1, { v -> vm.updateKind(k) { it.copy(opt1 = v) } }, label = { Text(lbl) },
                            singleLine = !k.multiSni, minLines = if (k.multiSni) 2 else 1, maxLines = if (k.multiSni) 5 else 1,
                            supportingText = if (k.multiSni) ({
                                Text("Several SNIs allowed, separated by commas. The first is the handshake target; each SNI gets its own link.")
                            }) else null,
                            modifier = Modifier.fillMaxWidth())
                    }
                    k.opt2Label?.let { lbl ->
                        OutlinedTextField(st.opt2, { v -> vm.updateKind(k) { it.copy(opt2 = v) } }, label = { Text(lbl) },
                            singleLine = true,
                            visualTransformation = if (k == Kind.SSH) PasswordVisualTransformation() else VisualTransformation.None,
                            modifier = Modifier.fillMaxWidth())
                    }
                }
                k.hint?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
                k.warning?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
            }
        }
    }
}

@Composable
fun ProgressScreen(s: UiState) {
    val listState = rememberLazyListState()
    LaunchedEffect(s.logs.size) { if (s.logs.isNotEmpty()) listState.animateScrollToItem(s.logs.size - 1) }
    Column(Modifier.fillMaxSize().statusBarsPadding().navigationBarsPadding().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(s.plan.labels[s.stepIndex.coerceIn(0, s.plan.labels.lastIndex)], style = MaterialTheme.typography.titleLarge)
        LinearProgressIndicator(progress = { s.progress }, Modifier.fillMaxWidth())
        Text("Step ${s.stepIndex.coerceIn(0, s.plan.labels.lastIndex) + 1} of ${s.plan.labels.size}")
        Card(Modifier.fillMaxWidth().weight(1f)) {
            LazyColumn(Modifier.padding(8.dp), state = listState) {
                items(s.logs) { Text(it, fontFamily = FontFamily.Monospace, fontSize = 11.sp) }
            }
        }
    }
}

@Composable
fun SuccessScreen(vm: MainViewModel, s: UiState) {
    val ctx = LocalContext.current
    var pending by remember { mutableStateOf<FileResult?>(null) }
    val save = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        val item = pending
        if (uri != null && item != null) {
            try {
                ctx.contentResolver.openOutputStream(uri)?.use { it.write(item.bytes) }
                Toast.makeText(ctx, "Saved", Toast.LENGTH_SHORT).show()
            } catch (e: Exception) {
                Toast.makeText(ctx, "Save failed: ${e.message}", Toast.LENGTH_LONG).show()
            }
        }
        pending = null
    }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).statusBarsPadding().navigationBarsPadding().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("INSTALLATION COMPLETE", style = MaterialTheme.typography.headlineSmall)
        Card { Text("Every config below contains secret keys. Anyone who has one can use your server. Keep them private.", Modifier.padding(12.dp)) }
        s.results.forEach { r ->
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(r.title, style = MaterialTheme.typography.titleMedium)
                    when (r) {
                        is FileResult -> {
                            Text(r.fileName, fontFamily = FontFamily.Monospace, fontSize = 12.sp)
                            Button({
                                val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                                val clip = ClipData.newPlainText("config", r.bytes.decodeToString())
                                clip.description.extras = PersistableBundle().apply { putBoolean("android.content.extra.IS_SENSITIVE", true) }
                                cm.setPrimaryClip(clip)
                                Toast.makeText(ctx, "Config copied", Toast.LENGTH_SHORT).show()
                            }, Modifier.fillMaxWidth()) { Text("COPY CONFIG") }
                            OutlinedButton({ pending = r; save.launch(r.fileName) }, Modifier.fillMaxWidth()) { Text("SAVE FILE") }
                            OutlinedButton({
                                val dir = File(ctx.cacheDir, "shared").apply { mkdirs() }
                                val file = File(dir, r.fileName).apply { writeBytes(r.bytes) }
                                val uri = FileProvider.getUriForFile(ctx, "${ctx.packageName}.fileprovider", file)
                                val send = Intent(Intent.ACTION_SEND).apply {
                                    type = "application/octet-stream"
                                    putExtra(Intent.EXTRA_STREAM, uri)
                                    addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                                }
                                ctx.startActivity(Intent.createChooser(send, "Share / open with"))
                            }, Modifier.fillMaxWidth()) { Text("Share / Open with…") }
                        }
                        is LinkResult -> {
                            Text(r.link, fontFamily = FontFamily.Monospace, fontSize = 11.sp, maxLines = 6)
                            Button({
                                val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                                val clip = ClipData.newPlainText("config", r.link)
                                clip.description.extras = PersistableBundle().apply { putBoolean("android.content.extra.IS_SENSITIVE", true) }
                                cm.setPrimaryClip(clip)
                                Toast.makeText(ctx, "Copied", Toast.LENGTH_SHORT).show()
                            }, Modifier.fillMaxWidth()) { Text("COPY") }
                            OutlinedButton({
                                val send = Intent(Intent.ACTION_SEND).apply { type = "text/plain"; putExtra(Intent.EXTRA_TEXT, r.link) }
                                ctx.startActivity(Intent.createChooser(send, "Share"))
                            }, Modifier.fillMaxWidth()) { Text("Share link…") }
                        }
                        is FailedResult -> {
                            Text("Failed: ${r.message}", color = MaterialTheme.colorScheme.error)
                            Text(r.recovery, style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }
            }
        }
        TextButton({ vm.backToForm() }) { Text("Done") }
    }
}

@Composable
fun FailureScreen(vm: MainViewModel, s: UiState) {
    Column(Modifier.fillMaxSize().statusBarsPadding().navigationBarsPadding().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("Installation failed", style = MaterialTheme.typography.headlineSmall, color = MaterialTheme.colorScheme.error)
        Text(s.error.orEmpty())
        s.recovery?.let { Text(it, style = MaterialTheme.typography.bodyMedium) }
        Card(Modifier.fillMaxWidth().weight(1f)) {
            LazyColumn(Modifier.padding(8.dp)) { items(s.logs.takeLast(60)) { Text(it, fontFamily = FontFamily.Monospace, fontSize = 11.sp) } }
        }
        if (s.canForgetHostKey) OutlinedButton({ vm.forgetHostKey() }, Modifier.fillMaxWidth()) { Text("Forget saved host key") }
        Button({ vm.backToForm() }, Modifier.fillMaxWidth()) { Text("Back") }
    }
}
