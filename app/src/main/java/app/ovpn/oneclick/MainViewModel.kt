package app.ovpn.oneclick

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.security.SecureRandom
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

enum class Screen { FORM, RUNNING, SUCCESS, FAILURE }

class HostPrompt(val hostId: String, val fingerprint: String, val answer: CompletableDeferred<Boolean>)

data class UiState(
    val form: ConnectionForm = ConnectionForm(),
    val saveCredentials: Boolean = false,
    val screen: Screen = Screen.FORM,
    val stepIndex: Int = 0,
    val logs: List<String> = emptyList(),
    val formError: String? = null,
    val error: String? = null,
    val recovery: String? = null,
    val plan: Plan = Plan(emptyList(), listOf("Connecting to VPS")),
    val results: List<ResultItem> = emptyList(),
    val hostPrompt: HostPrompt? = null,
    val canForgetHostKey: Boolean = false
) {
    /** Real progress: completed steps / total steps. */
    val progress: Float
        get() = if (screen == Screen.SUCCESS) 1f else stepIndex.coerceIn(0, plan.labels.size) / plan.labels.size.toFloat()
}

class MainViewModel(app: Application) : AndroidViewModel(app) {
    private val store = CredentialStore(app)
    private val known = KnownHosts(app)
    private val _state = MutableStateFlow(UiState())
    val state: StateFlow<UiState> = _state.asStateFlow()
    init {
        store.load()?.let { json ->
            ConnectionForm.fromJson(json)?.let { f -> _state.update { it.copy(form = f, saveCredentials = true) } }
        }
    }

    fun update(block: (ConnectionForm) -> ConnectionForm) =
        _state.update { it.copy(form = block(it.form), formError = null) }

    fun setSave(v: Boolean) = _state.update { it.copy(saveCredentials = v) }

    fun updateKind(k: Kind, block: (ProtoSetting) -> ProtoSetting) =
        update { f -> f.copy(protos = f.protos + (k to block(f.setting(k)))) }

    fun start() {
        val s = _state.value
        Validators.validate(s.form)?.let { msg -> _state.update { it.copy(formError = msg) }; return }
        if (s.saveCredentials) runCatching { store.save(s.form.toJson()) } else store.clear()

        val am = getApplication<Application>().assets
        val assets = (listOf("lib.sh") + Group.values().map { it.script })
            .associateWith { am.open(it).use { st -> st.readBytes().decodeToString() } }
        val clientName = newClientName()
        val plan = buildPlan(s.form)
        _state.update {
            it.copy(screen = Screen.RUNNING, plan = plan, stepIndex = 0, logs = emptyList(), results = emptyList(),
                error = null, recovery = null, canForgetHostKey = false)
        }

        val installer = SshInstaller(known, assets) { hostId, fp ->
            val d = CompletableDeferred<Boolean>()
            _state.update { it.copy(hostPrompt = HostPrompt(hostId, fp, d)) }
            d.await()
        }
        val listener = object : SshInstaller.Listener {
            override fun onStep(index: Int) = _state.update { it.copy(stepIndex = index) }
            override fun onLog(line: String) = _state.update { it.copy(logs = (it.logs + line).takeLast(300)) }
        }
        viewModelScope.launch {
            try {
                val results = installer.run(s.form, clientName, plan, listener)
                val failed = results.filterIsInstance<FailedResult>()
                if (results.isEmpty() || failed.size == results.size) {
                    val msg = failed.joinToString("\n") { "${it.title}: ${it.message}" }.ifEmpty { "Nothing was generated." }
                    _state.update { it.copy(screen = Screen.FAILURE, error = msg, recovery = failed.firstOrNull()?.recovery, results = results) }
                } else {
                    _state.update { it.copy(screen = Screen.SUCCESS, results = results) }
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                val (msg, rec) = SshInstaller.describe(e)
                _state.update {
                    it.copy(
                        screen = Screen.FAILURE, error = msg, recovery = rec,
                        canForgetHostKey = e.message.orEmpty().contains("HostKey has been changed", true)
                    )
                }
            }
        }
    }

    fun answerHostKey(ok: Boolean) {
        _state.value.hostPrompt?.answer?.complete(ok)
        _state.update { it.copy(hostPrompt = null) }
    }

    fun forgetHostKey() {
        val f = _state.value.form
        known.forget("${f.host.trim()}:${f.sshPort.trim()}")
        _state.update { it.copy(canForgetHostKey = false, recovery = "Saved host key removed. Go back and retry.") }
    }

    fun backToForm() {
        _state.update { it.copy(screen = Screen.FORM, hostPrompt = null, results = emptyList()) }
    }

    private fun newClientName(): String {
        val b = ByteArray(2).also { SecureRandom().nextBytes(it) }
        val ts = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date())
        return "phone-$ts-" + b.joinToString("") { "%02x".format(it) }
    }
}
