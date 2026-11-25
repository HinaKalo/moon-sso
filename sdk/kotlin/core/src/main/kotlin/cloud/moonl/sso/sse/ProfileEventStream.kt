package cloud.moonl.sso.sse

import cloud.moonl.sso.AccountApi
import cloud.moonl.sso.MoonSsoException
import cloud.moonl.sso.MoonSsoLogger
import cloud.moonl.sso.Profile
import cloud.moonl.sso.ProfileState
import cloud.moonl.sso.SessionExpiredException
import cloud.moonl.sso.TokenManager
import cloud.moonl.sso.UserEvent
import cloud.moonl.sso.debug
import cloud.moonl.sso.internal.SdkJson
import cloud.moonl.sso.warn
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.Call
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.IOException
import java.util.concurrent.TimeUnit
import kotlin.coroutines.coroutineContext

/** Connection state of the profile event stream. */
public enum class EventStreamState { STOPPED, CONNECTING, CONNECTED, WAITING_TO_RECONNECT }

/**
 * Live profile events over `GET /api/v1/me/events` (fetch-style SSE: Authorization header, never a
 * token in the URL). Reconnects with `Last-Event-ID` after the server's `retry:` delay (3–8 s
 * otherwise) plus jitter, refreshing the access token when needed. `user.updated` updates the cached
 * profile; password change / disable / delete / consent revocation trigger a refresh that either
 * confirms the session or ends it with SessionExpired.
 */
public class ProfileEventStream internal constructor(
    private val eventsUrl: suspend () -> String,
    baseHttp: OkHttpClient,
    private val tokens: TokenManager,
    private val account: AccountApi,
    private val profiles: ProfileState,
    private val logger: MoonSsoLogger,
    private val scope: CoroutineScope,
    private val ensureInitialized: suspend () -> Unit = {},
) {
    private val http: OkHttpClient = baseHttp.newBuilder()
        .readTimeout(70, TimeUnit.SECONDS) // the server pings every 25 s
        .callTimeout(0, TimeUnit.MILLISECONDS)
        .retryOnConnectionFailure(true)
        .build()

    private val _state = MutableStateFlow(EventStreamState.STOPPED)
    private val _events = MutableSharedFlow<UserEvent>(replay = 0, extraBufferCapacity = 64)
    private var job: Job? = null

    @Volatile
    private var lastEventId: String? = null

    @Volatile
    private var serverRetryMs: Long? = null

    /** Consecutive 401 answers; a second one in a row backs off instead of reconnecting at once. */
    private var unauthorizedInARow = 0

    /** Connection state. */
    public val state: StateFlow<EventStreamState> = _state.asStateFlow()

    /** Every event received (including `resync` and `token_expired`). */
    public val events: SharedFlow<UserEvent> = _events.asSharedFlow()

    /** Last received event id (sent as `Last-Event-ID` on reconnect). */
    public val lastReceivedEventId: String? get() = lastEventId

    /** Starts the stream (idempotent). */
    @Synchronized
    public fun start() {
        if (job?.isActive == true) return
        _state.value = EventStreamState.CONNECTING
        job = scope.launch { runLoop() }
    }

    /** Stops the stream; a later [start] resumes from the last event id. */
    @Synchronized
    public fun stop() {
        job?.cancel()
        job = null
        _state.value = EventStreamState.STOPPED
    }

    public val isRunning: Boolean get() = job?.isActive == true

    private suspend fun runLoop() {
        var failures = 0
        try {
            ensureInitialized()
            while (true) {
                coroutineContext.ensureActive()
                if (tokens.tokens.value == null) {
                    _state.value = EventStreamState.WAITING_TO_RECONNECT
                    tokens.tokens.first { it != null }
                }
                _state.value = EventStreamState.CONNECTING
                val outcome = try {
                    connectOnce()
                } catch (e: CancellationException) {
                    throw e
                } catch (e: SessionExpiredException) {
                    Outcome.SESSION_ENDED
                } catch (e: MoonSsoException) {
                    if (e.error == MoonSsoException.LOGIN_REQUIRED) Outcome.SESSION_ENDED else {
                        logger.debug("event stream failed: ${e.error}")
                        Outcome.FAILED
                    }
                } catch (e: IOException) {
                    logger.debug("event stream disconnected: ${e.javaClass.simpleName}")
                    Outcome.FAILED
                }
                when (outcome) {
                    Outcome.SESSION_ENDED -> {
                        // Wait for a new login, then resume.
                        failures = 0
                        continue
                    }
                    Outcome.RECONNECT_NOW -> {
                        failures = 0
                        continue
                    }
                    Outcome.CLOSED -> failures = 0
                    Outcome.FAILED -> failures++
                    Outcome.FORBIDDEN -> failures = maxOf(failures + 1, 4)
                }
                _state.value = EventStreamState.WAITING_TO_RECONNECT
                delay(reconnectDelay(failures))
            }
        } finally {
            if (_state.value != EventStreamState.STOPPED) _state.value = EventStreamState.STOPPED
        }
    }

    private fun reconnectDelay(failures: Int): Long {
        val base = serverRetryMs ?: (3_000L + kotlin.random.Random.nextLong(5_000L))
        val factor = if (failures <= 1) 1L else (1L shl (failures - 1).coerceAtMost(4))
        val jitter = kotlin.random.Random.nextLong(1_000L)
        return (base * factor).coerceAtMost(60_000L) + jitter
    }

    private enum class Outcome { CLOSED, RECONNECT_NOW, FAILED, FORBIDDEN, SESSION_ENDED }

    private suspend fun connectOnce(): Outcome {
        val token = tokens.accessToken()
        val url = eventsUrl()
        val request = Request.Builder()
            .url(url)
            .header("Authorization", "Bearer $token")
            .header("Accept", "text/event-stream")
            .header("Cache-Control", "no-cache")
            .apply { lastEventId?.takeIf { it.isNotEmpty() }?.let { header("Last-Event-ID", it) } }
            .get()
            .build()
        val call = http.newCall(request)
        val handle = coroutineContext[Job]?.invokeOnCompletion { call.cancel() }
        try {
            return withContext(Dispatchers.IO) { stream(call, token) }
        } finally {
            handle?.dispose()
        }
    }

    private suspend fun stream(call: Call, token: String): Outcome {
        call.execute().use { response ->
            when {
                response.code == 401 -> {
                    unauthorizedInARow++
                    tokens.refreshAfterUnauthorized(token)
                    return if (unauthorizedInARow >= 2) Outcome.FAILED else Outcome.RECONNECT_NOW
                }
                response.code == 403 || response.code == 404 -> {
                    logger.warn("event stream rejected with HTTP ${response.code}")
                    return Outcome.FORBIDDEN
                }
                !response.isSuccessful -> return Outcome.FAILED
            }
            unauthorizedInARow = 0
            _state.value = EventStreamState.CONNECTED
            val source = response.body?.source() ?: return Outcome.FAILED
            val received = ArrayList<SseEvent>()
            val parser = SseParser(onEvent = { received.add(it) }, onRetry = { serverRetryMs = it.coerceIn(500L, 300_000L) })
            parser.pushLine("") // start clean
            var outcome = Outcome.CLOSED
            while (true) {
                coroutineContext.ensureActive()
                val line = source.readUtf8Line() ?: break
                parser.pushLine(line)
                if (received.isEmpty()) continue
                val batch = received.toList()
                received.clear()
                for (ev in batch) {
                    ev.id?.let { lastEventId = it }
                    val result = handle(ev)
                    if (result != null) outcome = result
                }
                if (outcome == Outcome.RECONNECT_NOW) return outcome
            }
            return outcome
        }
    }

    /** Returns a non-null outcome when the connection should be replaced. */
    private suspend fun handle(ev: SseEvent): Outcome? {
        val event = try {
            val trimmed = ev.data.trim()
            val parsed = if (trimmed.isEmpty() || trimmed == "{}") UserEvent(type = ev.type) else {
                SdkJson.decodeFromString(UserEvent.serializer(), trimmed)
            }
            // The SSE "event:" field is authoritative for the type.
            if (ev.type != "message" || parsed.type.isEmpty()) parsed.copy(type = ev.type) else parsed
        } catch (e: Exception) {
            logger.warn("ignoring malformed event of type ${ev.type}")
            return null
        }
        _events.tryEmit(event)
        when (event.type) {
            UserEvent.USER_UPDATED -> applyUpdate(event)
            UserEvent.RESYNC -> refetch()
            UserEvent.TOKEN_EXPIRED -> {
                tokens.refresh()
                return Outcome.RECONNECT_NOW
            }
            UserEvent.USER_PASSWORD_CHANGED, UserEvent.USER_DISABLED, UserEvent.USER_DELETED, UserEvent.CONSENT_REVOKED -> {
                // Either confirms that this device keeps its session or ends it (SessionExpired).
                tokens.refresh()
                return Outcome.RECONNECT_NOW
            }
        }
        return null
    }

    private suspend fun applyUpdate(event: UserEvent) {
        val d = event.data
        val current = profiles.profile.value
        if (d?.sub == null || d.profileVersion == null) {
            refetch()
            return
        }
        val next = Profile(
            sub = d.sub,
            preferredUsername = d.preferredUsername ?: current?.preferredUsername,
            name = d.name ?: current?.name,
            nickname = d.nickname ?: current?.nickname,
            picture = d.picture,
            updatedAt = d.updatedAt ?: current?.updatedAt,
            profileVersion = d.profileVersion,
            totpEnabled = current?.totpEnabled,
        )
        profiles.update(next)
    }

    private suspend fun refetch() {
        try {
            account.getMe()
        } catch (e: CancellationException) {
            throw e
        } catch (e: MoonSsoException) {
            logger.debug("profile refetch failed: ${e.error}")
        }
    }
}
