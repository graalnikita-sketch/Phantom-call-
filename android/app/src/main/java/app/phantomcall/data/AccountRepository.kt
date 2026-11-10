package app.phantomcall.data

import android.content.Context
import app.phantomcall.identity.DeviceKey
import app.phantomcall.net.ApiClient
import app.phantomcall.net.ApiException
import app.phantomcall.protocol.ProtocolMessages

data class SessionInfo(val id: String, val createdAt: String, val expiresAt: String, val current: Boolean)

/** Account lifecycle: create, log in, list sessions, delete. Blocking; call off the main thread. */
class AccountRepository(private val context: Context, private val store: SecureStore) {

    fun phantomId(): String? = store.get(SecureStore.PHANTOM_ID)

    private fun api(): ApiClient = ApiClient(store.get(SecureStore.SERVER_URL) ?: throw ApiException(0, "no_server"))

    fun create(serverUrl: String): String {
        val api = ApiClient(serverUrl)
        DeviceKey.ensure(context)
        val spki = DeviceKey.publicKeySpki()
        val ch = api.challenge("register")
        val sig = DeviceKey.sign(ProtocolMessages.register(ch.getString("nonce"), spki))
        val res = api.register(ch.getString("challenge_id"), SecureStore.b64(spki), SecureStore.b64(sig))
        val id = res.getString("phantom_id")
        store.put(SecureStore.SERVER_URL, ApiClient.normalize(serverUrl))
        store.put(SecureStore.DEVICE_ID, res.getString("device_id"))
        store.put(SecureStore.PHANTOM_ID, id)
        login()
        return id
    }

    fun login(): String {
        val api = api()
        val deviceId = store.get(SecureStore.DEVICE_ID) ?: throw ApiException(0, "no_account")
        val ch = api.challenge("login", deviceId)
        val sig = DeviceKey.sign(ProtocolMessages.login(ch.getString("nonce"), deviceId))
        val token = api.login(ch.getString("challenge_id"), deviceId, SecureStore.b64(sig)).getString("token")
        store.put(SecureStore.TOKEN, token)
        return token
    }

    private fun <T> authed(block: (ApiClient, String) -> T): T {
        val api = api()
        val token = store.get(SecureStore.TOKEN) ?: login()
        return try {
            block(api, token)
        } catch (e: ApiException) {
            if (e.status != 401) throw e
            block(api, login())
        }
    }

    fun sessions(): List<SessionInfo> = authed { api, token ->
        val arr = api.me(token).getJSONArray("sessions")
        (0 until arr.length()).map {
            val s = arr.getJSONObject(it)
            SessionInfo(s.getString("session_id"), s.getString("created_at"), s.getString("expires_at"), s.getBoolean("current"))
        }
    }

    fun endSession(id: String) = authed { api, token -> api.deleteSession(token, id) }

    /** Deletes the account on the server, then everything on this phone. */
    fun deleteAccount() {
        authed { api, token -> api.deleteAccount(token) }
        wipeLocal()
    }

    /** Deletes local data and the device key. The server is not contacted. */
    fun wipeLocal() {
        store.wipe()
        DeviceKey.delete()
    }
}
