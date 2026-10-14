package app.ovpn.oneclick

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Saved connection details, encrypted with an AES-256-GCM key held in the Android Keystore. */
class CredentialStore(ctx: Context) {
    private val prefs = ctx.getSharedPreferences("saved_connection", Context.MODE_PRIVATE)
    private val alias = "ovpn_oneclick_aes"

    private fun key(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(alias, null) as? SecretKey)?.let { return it }
        val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        kg.init(
            KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
        )
        return kg.generateKey()
    }

    fun save(plain: String) {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, key())
        val blob = c.iv + c.doFinal(plain.toByteArray())
        prefs.edit().putString("blob", Base64.encodeToString(blob, Base64.NO_WRAP)).apply()
    }

    fun load(): String? {
        val stored = prefs.getString("blob", null) ?: return null
        return try {
            val blob = Base64.decode(stored, Base64.NO_WRAP)
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, blob.copyOfRange(0, 12)))
            String(c.doFinal(blob.copyOfRange(12, blob.size)))
        } catch (e: Exception) {
            null
        }
    }

    fun clear() = prefs.edit().clear().apply()
}

/** Trusted SSH host key fingerprints (public information, trust-on-first-use with user confirmation). */
class KnownHosts(ctx: Context) {
    private val prefs = ctx.getSharedPreferences("known_hosts", Context.MODE_PRIVATE)
    fun get(id: String): String? = prefs.getString(id, null)
    fun put(id: String, fp: String) = prefs.edit().putString(id, fp).apply()
    fun forget(id: String) = prefs.edit().remove(id).apply()
}
