package cloud.moonl.sso

import cloud.moonl.sso.dpop.DpopProofs
import cloud.moonl.sso.internal.HttpResult
import cloud.moonl.sso.internal.OAuthTransport
import cloud.moonl.sso.internal.RetryPolicy
import cloud.moonl.sso.internal.toError
import cloud.moonl.sso.jwt.IdTokenVerifier
import cloud.moonl.sso.jwt.unverifiedSubject
import cloud.moonl.sso.storage.PersistedState
import cloud.moonl.sso.storage.SessionStore
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.longOrNull

/**
 * Owns the session tokens: proactive refresh (at a fraction of the lifetime and before every call),
 * single-flight refresh (coroutine [Mutex] in-process plus the storage's cross-process lock),
 * atomic persistence of rotated refresh tokens, retry rules and session expiry.
 */
public class TokenManager internal constructor(
    private val config: MoonSsoConfig,
    private val discovery: DiscoveryClient,
    private val transport: OAuthTransport,
    private val store: SessionStore,
    private val idTokens: IdTokenVerifier,
    private val dpop: DpopProofs?,
    private val clock: () -> Long,
) {
    private val logger = config.logger
    private val refreshMutex = Mutex()
    private val _authState = MutableStateFlow<AuthState>(AuthState.Loading)
    private val _sessionExpired = MutableSharedFlow<SessionExpiredEvent>(replay = 0, extraBufferCapacity = 16)
    private val _tokens = MutableStateFlow<TokenSet?>(null)

    /** Current login state. */
    public val authState: StateFlow<AuthState> = _authState.asStateFlow()

    /** Emits when a refresh fails with `invalid_grant` and the session is discarded. */
    public val sessionExpired: SharedFlow<SessionExpiredEvent> = _sessionExpired.asSharedFlow()

    /** Current tokens (null when signed out). */
    public val tokens: StateFlow<TokenSet?> = _tokens.asStateFlow()

    internal fun onStoreChanged(s: PersistedState) {
        val t = s.tokens()
        _tokens.value = t
        val current = _authState.value
        _authState.value = when {
            t != null -> AuthState.SignedIn(s.sub, t.scopes, t.expiresAt)
            current is AuthState.SessionExpired -> current
            else -> AuthState.SignedOut
        }
    }

    /** Whether [t] reached the proactive refresh point (or expired). */
    internal fun needsRefresh(t: TokenSet): Boolean = clock() >= t.refreshDueAtMillis(config.refreshAtLifetimeFraction)

    /**
     * Returns an access token that is valid for the next request, refreshing first when 75% of its
     * lifetime is used (covers wake-up after sleep).
     *
     * @throws MoonSsoException `login_required` when signed out, [SessionExpiredException] when the
     * refresh token was rejected, or a transient error (network/5xx) that leaves the session intact.
     */
    public suspend fun accessToken(): String {
        val t = _tokens.value ?: throw notSignedIn()
        if (!needsRefresh(t)) return t.accessToken
        return refreshInternal(force = false, observedAccessToken = t.accessToken).accessToken
    }

    /** Refreshes now (single-flight: concurrent callers share one network request). */
    public suspend fun refresh(): TokenSet {
        val observed = _tokens.value?.accessToken ?: throw notSignedIn()
        return refreshInternal(force = true, observedAccessToken = observed)
    }

    /**
     * Forced refresh after a resource server rejected [rejectedAccessToken] with 401. When another
     * caller already replaced that token, the replacement is returned without a new request.
     */
    public suspend fun refreshAfterUnauthorized(rejectedAccessToken: String): TokenSet =
        refreshInternal(force = true, observedAccessToken = rejectedAccessToken)

    private suspend fun refreshInternal(force: Boolean, observedAccessToken: String?): TokenSet = refreshMutex.withLock {
        val cur = _tokens.value ?: throw notSignedIn()
        // Another coroutine refreshed while we waited for the mutex.
        if (observedAccessToken != null && cur.accessToken != observedAccessToken && !needsRefresh(cur)) return@withLock cur
        if (!force && !needsRefresh(cur)) return@withLock cur
        dpop?.key() // make sure the DPoP key exists before entering the storage transaction
        store.transaction { tx ->
            val fresh = tx.current.tokens() ?: throw notSignedIn()
            // Another process sharing the storage refreshed already: adopt its result.
            if (fresh.accessToken != cur.accessToken && !needsRefresh(fresh)) {
                logger.debug("adopting tokens refreshed by another process")
                return@transaction fresh
            }
            if (!force && !needsRefresh(fresh)) return@transaction fresh
            val refreshToken = fresh.refreshToken
                ?: return@transaction expire(tx, "no refresh token available")
            val doc = discovery.get()
            val result = transport.postForm(
                doc.tokenEndpoint,
                mapOf("grant_type" to "refresh_token", "refresh_token" to refreshToken, "client_id" to config.clientId),
                RetryPolicy.TRANSIENT,
            )
            if (!result.isSuccessful) {
                val err = result.toError()
                if (err.error == MoonSsoException.INVALID_GRANT) return@transaction expire(tx, err.errorDescription)
                throw err
            }
            val next = parseTokenResponse(result, previousRefreshToken = refreshToken)
            // Persist the rotated refresh token before anything else can fail.
            val subject = tx.current.sub
            tx.write(tx.current.withTokens(next, subject))
            next.idToken?.let { idt ->
                try {
                    val claims = idTokens.verify(idt, expectedNonce = null, accessToken = next.accessToken)
                    if (subject != null && claims.subject != subject) {
                        logger.warn("refreshed id_token has a different subject; keeping the previous id_token")
                        tx.write(tx.current.copy(idToken = fresh.idToken))
                    }
                } catch (e: MoonSsoException) {
                    logger.warn("refreshed id_token failed verification; keeping the previous id_token", e)
                    tx.write(tx.current.copy(idToken = fresh.idToken))
                }
            }
            tx.current.tokens() ?: next
        }
    }

    private suspend fun expire(tx: SessionStore.Tx, reason: String?): Nothing {
        logger.info("session expired: refresh token rejected")
        _authState.value = AuthState.SessionExpired(reason)
        tx.write(tx.current.signedOut())
        _sessionExpired.tryEmit(SessionExpiredEvent(reason))
        throw SessionExpiredException(reason)
    }

    /**
     * Redeems an authorization code. [redirectUri] is null for first-party challenge codes. The ID
     * token is verified (with [expectedNonce] for browser flows) before the session is stored.
     */
    internal suspend fun exchangeCode(code: String, verifier: String, redirectUri: String?, expectedNonce: String?): TokenSet {
        dpop?.key()
        val doc = discovery.get()
        val form = buildMap {
            put("grant_type", "authorization_code")
            put("code", code)
            put("code_verifier", verifier)
            put("client_id", config.clientId)
            redirectUri?.let { put("redirect_uri", it) }
        }
        // A replayed code revokes what it produced, so only retry when the request never arrived.
        val result = transport.postForm(doc.tokenEndpoint, form, RetryPolicy.SAFE)
        if (!result.isSuccessful) throw result.toError()
        val tokens = parseTokenResponse(result, previousRefreshToken = null)
        val idt = tokens.idToken
        val subject = if (idt != null) {
            idTokens.verify(idt, expectedNonce, tokens.accessToken).subject
        } else {
            if (expectedNonce != null && tokens.scopes.contains("openid")) {
                throw MoonSsoException(MoonSsoException.INVALID_RESPONSE, "token response has no id_token")
            }
            null
        }
        refreshMutex.withLock {
            store.transaction { tx -> tx.write(tx.current.withTokens(tokens, subject)) }
        }
        return tokens
    }

    /** Removes the local session and revokes the refresh token (failures are ignored). */
    public suspend fun signOut() {
        val refreshToken = refreshMutex.withLock {
            store.transaction { tx ->
                val rt = tx.current.refreshToken
                tx.write(tx.current.signedOut())
                rt
            }
        }
        _authState.value = AuthState.SignedOut
        if (refreshToken != null) {
            try {
                val doc = discovery.get()
                doc.revocationEndpoint?.let { endpoint ->
                    transport.postForm(
                        endpoint,
                        mapOf("token" to refreshToken, "token_type_hint" to "refresh_token", "client_id" to config.clientId),
                        RetryPolicy.NONE,
                    )
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                logger.debug("token revocation failed (ignored): ${e.javaClass.simpleName}")
            }
        }
    }

    internal fun parseTokenResponse(result: HttpResult, previousRefreshToken: String?): TokenSet {
        val obj = result.json() ?: throw MoonSsoException(MoonSsoException.INVALID_RESPONSE, "token response is not JSON", result.code)
        fun s(k: String) = (obj[k] as? JsonPrimitive)?.contentOrNull
        val accessToken = s("access_token")
            ?: throw MoonSsoException(MoonSsoException.INVALID_RESPONSE, "token response has no access_token", result.code)
        val expiresIn = (obj["expires_in"] as? JsonPrimitive)?.longOrNull ?: 300L
        val now = clock() / 1000
        return TokenSet(
            accessToken = accessToken,
            tokenType = s("token_type") ?: "Bearer",
            refreshToken = s("refresh_token") ?: previousRefreshToken,
            idToken = s("id_token"),
            scope = s("scope"),
            issuedAt = now,
            expiresAt = now + expiresIn,
        )
    }

    /** Background proactive refresh at [MoonSsoConfig.refreshAtLifetimeFraction] of the lifetime. */
    internal fun launchAutoRefresh(scope: CoroutineScope): Job = scope.launch {
        _tokens.map { it?.accessToken to it }.distinctUntilChanged { a, b -> a.first == b.first }.collectLatest { (_, t) ->
            var tokens = t ?: return@collectLatest
            var backoffMs = 5_000L
            while (true) {
                val wait = tokens.refreshDueAtMillis(config.refreshAtLifetimeFraction) - clock()
                if (wait > 0) delay(wait)
                try {
                    tokens = refreshInternal(force = false, observedAccessToken = null)
                    backoffMs = 5_000L
                } catch (e: CancellationException) {
                    throw e
                } catch (e: SessionExpiredException) {
                    return@collectLatest
                } catch (e: MoonSsoException) {
                    if (e.error == MoonSsoException.LOGIN_REQUIRED) return@collectLatest
                    logger.debug("background refresh failed (${e.error}); retrying in ${backoffMs / 1000}s")
                    delay(backoffMs)
                    backoffMs = (backoffMs * 2).coerceAtMost(5 * 60_000L)
                }
            }
        }
    }

    internal fun currentSubject(): String? = store.state.sub ?: unverifiedSubject(store.state.idToken)

    private fun notSignedIn() = MoonSsoException(MoonSsoException.LOGIN_REQUIRED, "not signed in")
}
