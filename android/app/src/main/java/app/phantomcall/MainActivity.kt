package app.phantomcall

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.fragment.app.FragmentActivity
import app.phantomcall.data.AccountRepository
import app.phantomcall.data.SecureStore
import app.phantomcall.ui.AppLock
import app.phantomcall.ui.AppRoot
import app.phantomcall.ui.LockScreen

class MainActivity : FragmentActivity() {
    private lateinit var store: SecureStore
    private var locked by mutableStateOf(false)

    private fun lockEnabled(): Boolean = runCatching { store.getBoolean(SecureStore.APP_LOCK, false) }.getOrDefault(false)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Keeps the app out of screenshots, screen recordings and the recent-apps preview.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        store = SecureStore(this)
        val repo = AccountRepository(applicationContext, store)
        locked = lockEnabled()

        setContent {
            MaterialTheme(colorScheme = darkColorScheme()) {
                Surface(Modifier.fillMaxSize()) {
                    if (locked) {
                        LockScreen(onUnlock = ::unlock)
                    } else {
                        AppRoot(
                            repo = repo,
                            store = store,
                            lockAvailable = { AppLock.available(this) },
                            confirmIdentity = { title, onSuccess ->
                                if (AppLock.available(this)) AppLock.prompt(this, title, onSuccess) else onSuccess()
                            },
                        )
                    }
                }
            }
        }
        if (locked) unlock()
    }

    private fun unlock() {
        if (!AppLock.available(this)) {
            // The phone's screen lock was removed after app lock was turned on;
            // there is nothing left to authenticate against.
            locked = false
            return
        }
        AppLock.prompt(this, "Разблокировать PHANTOM CALL") { locked = false }
    }

    override fun onStop() {
        super.onStop()
        if (lockEnabled()) locked = true
    }
}
