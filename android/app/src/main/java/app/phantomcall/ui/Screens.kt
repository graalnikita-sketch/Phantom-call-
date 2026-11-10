package app.phantomcall.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import app.phantomcall.data.AccountRepository
import app.phantomcall.data.SecureStore
import app.phantomcall.data.SessionInfo
import app.phantomcall.identity.DeviceKey
import app.phantomcall.net.ApiException
import app.phantomcall.protocol.ProtocolMessages
import java.io.IOException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private enum class Screen { HOME, PRIVACY }

fun describeError(e: Throwable): String = when (e) {
    is ApiException -> when (e.code) {
        "https_required" -> "Адрес сервера должен начинаться с https://"
        "rate_limited" -> "Слишком много попыток. Подождите и повторите."
        "key_already_registered" -> "Ключ этого телефона уже зарегистрирован на сервере."
        "no_server", "no_account" -> "Аккаунт на этом телефоне не найден."
        else -> "Сервер ответил ошибкой ${e.status} (${e.code})."
    }
    is IOException -> "Нет связи с сервером. Проверьте адрес и интернет."
    else -> "Ошибка: ${e.javaClass.simpleName}"
}

/** Runs blocking work off the main thread and reports the outcome on it. */
private fun <T> CoroutineScope.run(
    setBusy: (Boolean) -> Unit,
    setError: (String?) -> Unit,
    work: () -> T,
    done: (T) -> Unit,
) = launch {
    setBusy(true)
    setError(null)
    try {
        done(withContext(Dispatchers.IO) { work() })
    } catch (e: Exception) {
        setError(describeError(e))
    } finally {
        setBusy(false)
    }
}

@Composable
fun LockScreen(onUnlock: () -> Unit) {
    Column(
        Modifier.fillMaxSize().safeDrawingPadding().padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text("PHANTOM CALL заблокирован", style = MaterialTheme.typography.titleLarge)
        Spacer(Modifier.height(16.dp))
        Button(onClick = onUnlock) { Text("Разблокировать") }
    }
}

@Composable
fun AppRoot(repo: AccountRepository, store: SecureStore, lockAvailable: () -> Boolean, confirmIdentity: (String, () -> Unit) -> Unit) {
    var phantomId by remember { mutableStateOf(repo.phantomId()) }
    var screen by remember { mutableStateOf(Screen.HOME) }
    val id = phantomId
    when {
        id == null -> Onboarding(repo) { phantomId = it }
        screen == Screen.PRIVACY -> Privacy(repo, store, lockAvailable, confirmIdentity, onBack = { screen = Screen.HOME }, onAccountGone = {
            phantomId = null
            screen = Screen.HOME
        })
        else -> Home(id) { screen = Screen.PRIVACY }
    }
}

@Composable
private fun Onboarding(repo: AccountRepository, onCreated: (String) -> Unit) {
    val scope = rememberCoroutineScope()
    var url by remember { mutableStateOf("https://") }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    Column(Modifier.fillMaxSize().safeDrawingPadding().verticalScroll(rememberScrollState()).padding(24.dp)) {
        Text("PHANTOM CALL", style = MaterialTheme.typography.headlineMedium)
        Spacer(Modifier.height(12.dp))
        Text("Аккаунт создаётся без номера телефона и без пароля. Телефон сам создаст ключ в защищённом хранилище; этот ключ и есть ваша личность в сети.")
        Spacer(Modifier.height(8.dp))
        Text("Восстановить аккаунт нельзя: при потере телефона или удалении приложения понадобится новый PHANTOM ID.", color = MaterialTheme.colorScheme.error)
        Spacer(Modifier.height(16.dp))
        OutlinedTextField(value = url, onValueChange = { url = it }, label = { Text("Адрес сервера") }, singleLine = true, enabled = !busy, modifier = Modifier.fillMaxWidth())
        Spacer(Modifier.height(16.dp))
        Button(enabled = !busy, modifier = Modifier.fillMaxWidth(), onClick = {
            scope.run({ busy = it }, { error = it }, { repo.create(url) }, onCreated)
        }) { Text("Создать аккаунт") }
        if (busy) {
            Spacer(Modifier.height(16.dp))
            CircularProgressIndicator()
        }
        error?.let {
            Spacer(Modifier.height(16.dp))
            Text(it, color = MaterialTheme.colorScheme.error)
        }
    }
}

@Composable
private fun Home(phantomId: String, onPrivacy: () -> Unit) {
    val fingerprint = remember { runCatching { ProtocolMessages.fingerprint(DeviceKey.publicKeySpki()) }.getOrDefault("недоступен") }
    val protection = remember { runCatching { DeviceKey.protectionLevel() }.getOrDefault("неизвестно") }
    Column(Modifier.fillMaxSize().safeDrawingPadding().verticalScroll(rememberScrollState()).padding(24.dp)) {
        Text("Ваш PHANTOM ID", style = MaterialTheme.typography.labelLarge)
        SelectionContainer { Text(phantomId, style = MaterialTheme.typography.headlineSmall, fontFamily = FontFamily.Monospace) }
        Spacer(Modifier.height(20.dp))
        Text("Отпечаток ключа устройства", style = MaterialTheme.typography.labelLarge)
        SelectionContainer { Text(fingerprint, fontFamily = FontFamily.Monospace) }
        Spacer(Modifier.height(20.dp))
        Text("Где хранится ключ", style = MaterialTheme.typography.labelLarge)
        Text(protection)
        Spacer(Modifier.height(20.dp))
        Text("Звонки в этой сборке ещё не работают: это фаза 1, она проверяет создание аккаунта и хранение ключа.")
        Spacer(Modifier.height(24.dp))
        Button(onClick = onPrivacy, modifier = Modifier.fillMaxWidth()) { Text("Приватность и безопасность") }
    }
}

@Composable
private fun Privacy(
    repo: AccountRepository,
    store: SecureStore,
    lockAvailable: () -> Boolean,
    confirmIdentity: (String, () -> Unit) -> Unit,
    onBack: () -> Unit,
    onAccountGone: () -> Unit,
) {
    val scope = rememberCoroutineScope()
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var lockOn by remember { mutableStateOf(store.getBoolean(SecureStore.APP_LOCK, false)) }
    var sessions by remember { mutableStateOf<List<SessionInfo>?>(null) }
    var confirm by remember { mutableStateOf<Pair<String, () -> Unit>?>(null) }

    fun reload() = scope.run({ busy = it }, { error = it }, { repo.sessions() }) { sessions = it }
    LaunchedEffect(Unit) { reload() }

    Column(Modifier.fillMaxSize().safeDrawingPadding().verticalScroll(rememberScrollState()).padding(24.dp)) {
        TextButton(onClick = onBack) { Text("← Назад") }
        Text("Приватность и безопасность", style = MaterialTheme.typography.headlineSmall)
        Spacer(Modifier.height(16.dp))

        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text("Блокировка приложения")
                Text("Отпечаток, лицо или PIN телефона при каждом входе", style = MaterialTheme.typography.bodySmall)
            }
            Switch(checked = lockOn, onCheckedChange = { want ->
                error = null
                if (want && !lockAvailable()) {
                    error = "Сначала включите блокировку экрана в настройках телефона."
                } else {
                    confirmIdentity(if (want) "Включить блокировку" else "Отключить блокировку") {
                        store.putBoolean(SecureStore.APP_LOCK, want)
                        lockOn = want
                    }
                }
            })
        }

        Spacer(Modifier.height(24.dp))
        Text("Активные сессии", style = MaterialTheme.typography.titleMedium)
        val list = sessions
        if (list == null) {
            Text(if (busy) "Загрузка…" else "Не удалось загрузить.", style = MaterialTheme.typography.bodySmall)
        } else {
            list.forEach { s ->
                Row(Modifier.fillMaxWidth().padding(vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(if (s.current) "Эта сессия" else "Сессия ${s.id}")
                        Text("создана ${s.createdAt}", style = MaterialTheme.typography.bodySmall)
                    }
                    if (!s.current) {
                        TextButton(enabled = !busy, onClick = {
                            scope.run({ busy = it }, { error = it }, { repo.endSession(s.id) }) { reload() }
                        }) { Text("Завершить") }
                    }
                }
            }
        }

        Spacer(Modifier.height(24.dp))
        Text("Удаление данных", style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(8.dp))
        OutlinedButton(enabled = !busy, modifier = Modifier.fillMaxWidth(), onClick = {
            confirm = "Аккаунт будет удалён на сервере, а ключ и все данные — с этого телефона. Отменить это нельзя." to {
                scope.run({ busy = it }, { error = it }, { repo.deleteAccount() }) { onAccountGone() }
            }
        }) { Text("Удалить аккаунт полностью") }
        Spacer(Modifier.height(8.dp))
        OutlinedButton(enabled = !busy, modifier = Modifier.fillMaxWidth(), onClick = {
            confirm = "Ключ и данные будут стёрты только с этого телефона. Запись на сервере останется, и удалить её потом будет нечем. Используйте, только если сервер недоступен." to {
                scope.run({ busy = it }, { error = it }, { repo.wipeLocal() }) { onAccountGone() }
            }
        }) { Text("Стереть данные только на телефоне") }

        error?.let {
            Spacer(Modifier.height(16.dp))
            Text(it, color = MaterialTheme.colorScheme.error)
        }
    }

    confirm?.let { (text, action) ->
        AlertDialog(
            onDismissRequest = { confirm = null },
            title = { Text("Вы уверены?") },
            text = { Text(text) },
            confirmButton = {
                TextButton(onClick = {
                    confirm = null
                    confirmIdentity("Подтвердите удаление", action)
                }) { Text("Удалить") }
            },
            dismissButton = { TextButton(onClick = { confirm = null }) { Text("Отмена") } },
        )
    }
}
