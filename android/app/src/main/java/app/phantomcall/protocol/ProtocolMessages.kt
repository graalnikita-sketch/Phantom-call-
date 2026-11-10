package app.phantomcall.protocol

import java.security.MessageDigest

/**
 * The exact byte strings a device signs. They must stay byte-identical to
 * server/internal/auth/auth.go; the shared test vectors guard that.
 */
object ProtocolMessages {
    private const val REGISTER_PREFIX = "PHANTOM-CALL/v1/register\n"
    private const val LOGIN_PREFIX = "PHANTOM-CALL/v1/login\n"

    fun register(nonce: String, spki: ByteArray): ByteArray =
        (REGISTER_PREFIX + nonce + "\n" + sha256Hex(spki)).toByteArray(Charsets.UTF_8)

    fun login(nonce: String, deviceId: String): ByteArray =
        (LOGIN_PREFIX + nonce + "\n" + deviceId).toByteArray(Charsets.UTF_8)

    fun sha256Hex(data: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(data).joinToString("") { "%02x".format(it) }

    /** Short human-readable form of a public key, for display only. */
    fun fingerprint(spki: ByteArray): String =
        sha256Hex(spki).take(32).uppercase().chunked(4).joinToString(" ")
}
