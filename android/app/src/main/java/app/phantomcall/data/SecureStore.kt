package app.phantomcall.data

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import org.json.JSONObject

/**
 * Small encrypted key-value store. Values are kept in one JSON object,
 * encrypted with AES-256-GCM under a key that lives in Android Keystore.
 */
class SecureStore(context: Context) {
    private val file = context.applicationContext.getFileStreamPath("state.bin")
    private val lock = Any()

    private fun key(): SecretKey {
        val ks = KeyStore.getInstance(STORE).apply { load(null) }
        (ks.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        val spec = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build()
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, STORE).apply { init(spec) }.generateKey()
    }

    private fun readAll(): JSONObject {
        if (!file.exists()) return JSONObject()
        val blob = file.readBytes()
        if (blob.size < IV_LEN + 16) return JSONObject()
        val cipher = Cipher.getInstance(TRANSFORM)
        cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, blob, 0, IV_LEN))
        return JSONObject(String(cipher.doFinal(blob, IV_LEN, blob.size - IV_LEN), Charsets.UTF_8))
    }

    private fun writeAll(obj: JSONObject) {
        val cipher = Cipher.getInstance(TRANSFORM)
        cipher.init(Cipher.ENCRYPT_MODE, key()) // Keystore picks a fresh random IV
        val ct = cipher.doFinal(obj.toString().toByteArray(Charsets.UTF_8))
        val tmp = java.io.File(file.parentFile, file.name + ".tmp")
        tmp.writeBytes(cipher.iv + ct)
        if (!tmp.renameTo(file)) error("cannot replace state file")
    }

    fun get(name: String): String? = synchronized(lock) { readAll().optString(name, "").ifEmpty { null } }

    fun put(name: String, value: String?) = synchronized(lock) {
        val all = readAll()
        if (value == null) all.remove(name) else all.put(name, value)
        writeAll(all)
    }

    fun getBoolean(name: String, default: Boolean): Boolean = get(name)?.toBooleanStrictOrNull() ?: default

    fun putBoolean(name: String, value: Boolean) = put(name, value.toString())

    /** Removes every stored value and the encryption key itself. */
    fun wipe() = synchronized(lock) {
        file.delete()
        KeyStore.getInstance(STORE).apply { load(null) }.deleteEntry(ALIAS)
    }

    companion object {
        private const val STORE = "AndroidKeyStore"
        private const val ALIAS = "phantom_local_store_v1"
        private const val TRANSFORM = "AES/GCM/NoPadding"
        private const val IV_LEN = 12

        const val SERVER_URL = "server_url"
        const val PHANTOM_ID = "phantom_id"
        const val DEVICE_ID = "device_id"
        const val TOKEN = "token"
        const val APP_LOCK = "app_lock"

        fun b64(data: ByteArray): String = Base64.encodeToString(data, Base64.NO_WRAP)
    }
}
