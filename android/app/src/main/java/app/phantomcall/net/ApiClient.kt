package app.phantomcall.net

import java.net.HttpURLConnection
import java.net.URL
import javax.net.ssl.HttpsURLConnection
import org.json.JSONObject

class ApiException(val status: Int, val code: String) : Exception("HTTP $status: $code")

/**
 * Minimal client for the Phase 1 server API (docs/API.md). HTTPS only:
 * plain-HTTP addresses are refused before any request is made.
 */
class ApiClient(baseUrl: String) {
    private val base: String = normalize(baseUrl)

    fun challenge(purpose: String, deviceId: String? = null): JSONObject =
        request("POST", "/v1/challenges", null, JSONObject().put("purpose", purpose).apply { if (deviceId != null) put("device_id", deviceId) })!!

    fun register(challengeId: String, publicKeyB64: String, signatureB64: String): JSONObject =
        request("POST", "/v1/accounts", null, JSONObject().put("challenge_id", challengeId).put("public_key", publicKeyB64).put("signature", signatureB64))!!

    fun login(challengeId: String, deviceId: String, signatureB64: String): JSONObject =
        request("POST", "/v1/sessions", null, JSONObject().put("challenge_id", challengeId).put("device_id", deviceId).put("signature", signatureB64))!!

    fun me(token: String): JSONObject = request("GET", "/v1/me", token, null)!!

    fun deleteSession(token: String, sessionId: String) {
        request("DELETE", "/v1/sessions/$sessionId", token, null)
    }

    fun deleteAccount(token: String) {
        request("DELETE", "/v1/me", token, null)
    }

    private fun request(method: String, path: String, token: String?, body: JSONObject?): JSONObject? {
        val conn = URL(base + path).openConnection() as? HttpsURLConnection ?: throw ApiException(0, "https_required")
        try {
            conn.requestMethod = method
            conn.connectTimeout = 10_000
            conn.readTimeout = 10_000
            conn.instanceFollowRedirects = false
            conn.setRequestProperty("Accept", "application/json")
            if (token != null) conn.setRequestProperty("Authorization", "Bearer $token")
            if (body != null) {
                conn.doOutput = true
                conn.setRequestProperty("Content-Type", "application/json")
                conn.outputStream.use { it.write(body.toString().toByteArray(Charsets.UTF_8)) }
            }
            val status = conn.responseCode
            val stream = if (status in 200..299) conn.inputStream else conn.errorStream
            val text = stream?.use { String(it.readBytes(), Charsets.UTF_8) }.orEmpty()
            if (status !in 200..299) {
                val code = runCatching { JSONObject(text).optString("error", "unknown") }.getOrDefault("unknown")
                throw ApiException(status, code)
            }
            return if (status == HttpURLConnection.HTTP_NO_CONTENT || text.isBlank()) null else JSONObject(text)
        } finally {
            conn.disconnect()
        }
    }

    companion object {
        fun normalize(url: String): String {
            val u = url.trim().trimEnd('/')
            if (!u.startsWith("https://") || u.length <= "https://".length) throw ApiException(0, "https_required")
            return u
        }
    }
}
