package app.phantomcall.identity

import android.content.Context
import android.content.pm.PackageManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/**
 * The device identity: an ECDSA P-256 key pair generated inside Android
 * Keystore. The private key is never exported and never leaves the device.
 */
object DeviceKey {
    private const val STORE = "AndroidKeyStore"
    private const val ALIAS = "phantom_device_identity_v1"

    private fun keyStore(): KeyStore = KeyStore.getInstance(STORE).apply { load(null) }

    fun exists(): Boolean = keyStore().containsAlias(ALIAS)

    /** Creates the key if it does not exist yet. StrongBox is used when the phone has it. */
    fun ensure(context: Context) {
        if (exists()) return
        val hasStrongBox = context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        if (hasStrongBox) {
            try {
                generate(strongBox = true)
                return
            } catch (_: StrongBoxUnavailableException) {
                // fall through to the regular hardware-backed keystore
            }
        }
        generate(strongBox = false)
    }

    private fun generate(strongBox: Boolean) {
        val spec = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setIsStrongBoxBacked(strongBox)
            .build()
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, STORE).apply { initialize(spec) }.generateKeyPair()
    }

    /** X.509 SubjectPublicKeyInfo, DER. */
    fun publicKeySpki(): ByteArray =
        keyStore().getCertificate(ALIAS)?.publicKey?.encoded ?: error("device key is missing")

    /** ECDSA with SHA-256, ASN.1 DER signature. */
    fun sign(message: ByteArray): ByteArray {
        val key = keyStore().getKey(ALIAS, null) as? PrivateKey ?: error("device key is missing")
        return Signature.getInstance("SHA256withECDSA").run {
            initSign(key)
            update(message)
            sign()
        }
    }

    /** Where the private key really lives, as reported by the system. */
    fun protectionLevel(): String {
        val key = keyStore().getKey(ALIAS, null) as? PrivateKey ?: return "ключ отсутствует"
        val info = KeyFactory.getInstance(key.algorithm, STORE).getKeySpec(key, KeyInfo::class.java)
        return if (android.os.Build.VERSION.SDK_INT >= 31) {
            when (info.securityLevel) {
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> "StrongBox (отдельный защищённый чип)"
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "TEE (защищённая среда процессора)"
                KeyProperties.SECURITY_LEVEL_SOFTWARE -> "программное хранилище (слабее)"
                else -> "неизвестно"
            }
        } else {
            @Suppress("DEPRECATION")
            if (info.isInsideSecureHardware) "аппаратное хранилище" else "программное хранилище (слабее)"
        }
    }

    fun delete() {
        keyStore().deleteEntry(ALIAS)
    }
}
