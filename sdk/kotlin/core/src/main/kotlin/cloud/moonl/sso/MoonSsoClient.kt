package cloud.moonl.sso

import cloud.moonl.sso.dpop.DpopKeyProvider
import cloud.moonl.sso.dpop.DpopProofs
import cloud.moonl.sso.dpop.StoredDpopKeyProvider
import cloud.moonl.sso.internal.BrowserAuthorization
import cloud.moonl.sso.internal.FirstPartyLogin
import cloud.moonl.sso.internal.OAuthTransport
import cloud.moonl.sso.internal.UserAgentInterceptor
import cloud.moonl.sso.internal.decode
import cloud.moonl.sso.internal.requireSuccess
import cloud.moonl.sso.internal.send
import cloud.moonl.sso.jwt.AccessTokenVerifier
import cloud.moonl.sso.jwt.IdTokenVerifier
import cloud.moonl.sso.jwt.JwksCache
import cloud.moonl.sso.okhttp.MoonSsoAuthInterceptor
import cloud.moonl.sso.okhttp.MoonSsoAuthenticator
import cloud.moonl.sso.okhttp.TokenHostPolicy
import cloud.moonl.sso.sse.ProfileEventStream
import cloud.moonl.sso.storage.CrossProcessLock
import cloud.moonl.sso.storage.InMemorySecureStorage
import cloud.moonl.sso.storage.NoCrossProcessLock
import cloud.moonl.sso.storage.SecureStorage
import cloud.moonl.sso.storage.SessionStore
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import okhttp3.Dispatcher
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.OkHttpClient
import okhttp3.Request
import java.util.concurrent.TimeUnit

/**
 * Entry point of the SDK for one client application: sign-in (first-party challenge, OTP, native
 * registration, browser authorization code + PKCE), token lifecycle, account API and live profile
 * events. Create one instance per client_id and keep it for the lifetime of the process.
 *
 * Platform modules provide ready-made factories (`MoonSsoAndroid.create`, `MoonSsoDesktop.create`).
 */
public class MoonSsoClient private constructor(
    public val config: MoonSsoConfig,
    storage: SecureStorage,
    dpopKeyProvider: DpopKeyProvider?,
    crossProcessLock: CrossProcessLock,
    baseHttp: OkHttpClient,
    private val clock: () -> Long,
    ioDispatcher: CoroutineDispatcher,
) {
    private val logger = config.logger
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val initMutex = Mutex()

    @Volatile
    private var initialized = false
    private var autoRefreshJob: Job? = null

    /**
     * OkHttp client for the SDK's own OAuth calls: no auth interceptor, separate dispatcher (no
     * deadlock with API calls blocked in the interceptor) and no silent connection-level retries —
     * a silent retry would replay the same DPoP proof (rejected as a jti replay) or an authorization
     * code (revoking the session). [OAuthTransport] applies the retry rules with fresh proofs instead.
     */
    private val oauthHttp: OkHttpClient = baseHttp.newBuilder()
        .dispatcher(Dispatcher())
        .retryOnConnectionFailure(false)
        .addInterceptor(UserAgentInterceptor(config.userAgent))
        .build()

    private val store = SessionStore(storage, crossProcessLock, config.issuer, config.clientId, ioDispatcher, logger)

    /** Discovery document cache (1 hour, stale on failure). */
    public val discovery: DiscoveryClient = DiscoveryClient(config.issuer, oauthHttp, clock)

    private val jwks = JwksCache(discovery, oauthHttp, clock)

    /** ID token verification against the issuer JWKS. */
    public val idTokenVerifier: IdTokenVerifier = IdTokenVerifier(config.issuer, config.clientId, jwks, clock)

    /** Local access token validation for resource servers. */
    public val accessTokenVerifier: AccessTokenVerifier = AccessTokenVerifier(config.issuer, jwks, clock)

    private val dpop: DpopProofs? = if (config.useDpop) {
        DpopProofs(dpopKeyProvider ?: StoredDpopKeyProvider(store), clock)
    } else {
        null
    }

    private val transport = OAuthTransport(oauthHttp, dpop, logger)

    /** Token lifecycle (proactive and single-flight refresh, persistence, session expiry). */
    public val tokenManager: TokenManager = TokenManager(config, discovery, transport, store, idTokenVerifier, dpop, clock)

    private val profiles = ProfileState(store)
    private val firstParty = FirstPartyLogin(config, discovery, transport, tokenManager, dpop != null)
    private val browser = BrowserAuthorization(config, discovery, tokenManager, dpop, clock)

    private val hostPolicy: TokenHostPolicy = run {
        val issuerHost = config.issuer.toHttpUrl()
        val trusted = config.trustedApiHosts.map { it.lowercase() }.toSet()
        TokenHostPolicy { url ->
            (url.host == issuerHost.host && url.port == issuerHost.port && url.scheme == issuerHost.scheme) ||
                (url.isHttps && url.host.lowercase() in trusted)
        }
    }

    /** Interceptor attaching the access token (with proactive refresh) to requests for the issuer and [MoonSsoConfig.trustedApiHosts]. */
    public val authInterceptor: MoonSsoAuthInterceptor = MoonSsoAuthInterceptor(tokenManager, hostPolicy)

    /** Authenticator that refreshes once and replays a request after 401. */
    public val authenticator: MoonSsoAuthenticator = MoonSsoAuthenticator(tokenManager, hostPolicy)

    /** OkHttp client with [authInterceptor] and [authenticator] installed, for the app's own API calls. */
    public val httpClient: OkHttpClient = baseHttp.newBuilder()
        .addInterceptor(UserAgentInterceptor(config.userAgent))
        .addInterceptor(authInterceptor)
        .authenticator(authenticator)
        .build()

    /** Account API (`/api/v1/me`). */
    public val account: AccountApi = AccountApi(config.issuer, httpClient, profiles)

    /** Live profile events (SSE). Call [ProfileEventStream.start] when the UI is visible. */
    public val events: ProfileEventStream = ProfileEventStream(
        eventsUrl = { discovery.get().eventsEndpoint ?: "${config.issuer}/api/v1/me/events" },
        baseHttp = oauthHttp,
        tokens = tokenManager,
        account = account,
        profiles = profiles,
        logger = logger,
        scope = scope,
        ensureInitialized = { initialize() },
    )

    init {
        store.onChange = { s ->
            tokenManager.onStoreChanged(s)
            profiles.onStoreChanged(s.profile)
        }
    }

    /** Login state. */
    public val authState: StateFlow<AuthState> get() = tokenManager.authState

    /** Emits once each time the session ends with `invalid_grant`. */
    public val sessionExpired: SharedFlow<SessionExpiredEvent> get() = tokenManager.sessionExpired

    /** Cached profile of the signed-in user. */
    public val profile: StateFlow<Profile?> get() = profiles.profile

    /** Emits every time the cached profile changes (API calls, SSE events). */
    public val profileChanges: SharedFlow<Profile> get() = profiles.changes

    /** Current tokens (null when signed out). */
    public val tokens: StateFlow<TokenSet?> get() = tokenManager.tokens

    /** Reads the stored session. Called automatically by every operation; call it early to restore the UI. */
    public suspend fun initialize() {
        if (initialized) return
        initMutex.withLock {
            if (initialized) return
            val s = store.reload()
            tokenManager.onStoreChanged(s)
            profiles.onStoreChanged(s.profile)
            if (config.autoRefresh) autoRefreshJob = tokenManager.launchAutoRefresh(scope)
            initialized = true
        }
    }

    /** Valid access token (refreshed first when 75% of its lifetime is used). */
    public suspend fun accessToken(): String {
        initialize()
        return tokenManager.accessToken()
    }

    /**
     * First-party login with username and password (`/oauth/authorize-challenge`).
     * @throws OtpRequiredException when a TOTP code is needed: call [submitOtp].
     * @throws PasswordChangeRequiredException when the password must be changed in the browser.
     */
    public suspend fun signInWithPassword(username: String, password: String, scopes: List<String> = config.scopes): TokenSet {
        initialize()
        return firstParty.signIn(username.trim(), password, scopes.joinToString(" ")).also { afterLogin() }
    }

    /** Second step of [signInWithPassword]; reuses the PKCE verifier of the first step. */
    public suspend fun submitOtp(challenge: OtpChallenge, otp: String): TokenSet {
        initialize()
        return firstParty.submitOtp(challenge, otp).also { afterLogin() }
    }

    /**
     * Creates an account inside a first-party app (`/api/v1/native/register`) and signs it in.
     * Validation errors are `MoonSsoException` with HTTP 422 and [MoonSsoException.field];
     * closed registration is `registration_closed` (403).
     */
    public suspend fun register(
        username: String,
        password: String,
        displayName: String? = null,
        scopes: List<String> = config.scopes,
    ): TokenSet {
        initialize()
        return firstParty.register(username.trim(), password, displayName, scopes.joinToString(" ")).also { afterLogin() }
    }

    /** Builds a browser authorization request (PKCE S256, state, nonce, dpop_jkt). Persist the result until the callback arrives. */
    public suspend fun createAuthorizationRequest(
        redirectUri: String,
        scopes: List<String> = config.scopes,
        prompt: String? = null,
        loginHint: String? = null,
        extraParameters: Map<String, String> = emptyMap(),
    ): PendingAuthorization {
        initialize()
        return browser.create(redirectUri, scopes.joinToString(" "), prompt, loginHint, extraParameters)
    }

    /** Validates the redirect (`state`, `iss`, `error`) and exchanges the code for tokens. */
    public suspend fun completeAuthorization(pending: PendingAuthorization, callbackUri: String): TokenSet {
        initialize()
        return browser.complete(pending, callbackUri).also { afterLogin() }
    }

    private suspend fun afterLogin() {
        // Fill the profile cache from the verified ID token claims when no profile is cached yet.
        if (profiles.profile.value != null) return
        val idt = tokens.value?.idToken ?: return
        try {
            val c = idTokenVerifier.verify(idt)
            fun str(k: String) = (c.claims[k] as? kotlinx.serialization.json.JsonPrimitive)?.takeIf { it.isString }?.content
            fun num(k: String) = (c.claims[k] as? kotlinx.serialization.json.JsonPrimitive)?.content?.toLongOrNull()
            if (c.claims.containsKey("profile_version")) {
                profiles.update(
                    Profile(
                        sub = c.subject,
                        preferredUsername = str("preferred_username"),
                        name = str("name"),
                        nickname = str("nickname"),
                        picture = str("picture"),
                        updatedAt = num("updated_at"),
                        profileVersion = num("profile_version") ?: 0,
                    ),
                )
            }
        } catch (e: MoonSsoException) {
            logger.debug("could not read profile claims from id_token: ${e.error}")
        }
    }

    /** Verified claims of the current ID token, or null when signed out / no ID token. */
    public suspend fun idTokenClaims(): IdTokenClaims? {
        initialize()
        val idt = tokens.value?.idToken ?: return null
        return idTokenVerifier.verify(idt)
    }

    /** `GET /api/v1/registration`: whether self-service registration is open and the rules. */
    public suspend fun registrationInfo(): RegistrationInfo =
        oauthHttp.send(Request.Builder().url("${config.issuer}/api/v1/registration").get().build()).requireSuccess().decode()

    /** Ends the session locally, stops the event stream and revokes the refresh token (failures ignored). */
    public suspend fun signOut() {
        initialize()
        events.stop()
        tokenManager.signOut()
    }

    /** RP-initiated logout URL (`end_session_endpoint`) for browser flows; call before [signOut] to include the ID token hint. */
    public suspend fun endSessionUrl(postLogoutRedirectUri: String? = null, state: String? = null): String? {
        val endpoint = discovery.get().endSessionEndpoint ?: return null
        return endpoint.toHttpUrl().newBuilder().apply {
            addQueryParameter("client_id", config.clientId)
            tokens.value?.idToken?.let { addQueryParameter("id_token_hint", it) }
            postLogoutRedirectUri?.let { addQueryParameter("post_logout_redirect_uri", it) }
            state?.let { addQueryParameter("state", it) }
        }.build().toString()
    }

    /** Stops background work (auto refresh, event stream). The instance must not be used afterwards. */
    public fun close() {
        events.stop()
        autoRefreshJob?.cancel()
        scope.cancel()
        oauthHttp.dispatcher.executorService.shutdown()
    }

    /** Builder for [MoonSsoClient]. */
    public class Builder(private val config: MoonSsoConfig) {
        private var storage: SecureStorage = InMemorySecureStorage()
        private var dpopKeyProvider: DpopKeyProvider? = null
        private var lock: CrossProcessLock = NoCrossProcessLock
        private var http: OkHttpClient? = null
        private var clock: () -> Long = System::currentTimeMillis
        private var io: CoroutineDispatcher = Dispatchers.IO

        /** Secure storage for the session (default: in memory only). */
        public fun storage(storage: SecureStorage): Builder = apply { this.storage = storage }

        /** DPoP key source (default: software key stored inside [storage]). */
        public fun dpopKeyProvider(provider: DpopKeyProvider): Builder = apply { this.dpopKeyProvider = provider }

        /** Lock shared by processes that use the same storage (default: none). */
        public fun crossProcessLock(lock: CrossProcessLock): Builder = apply { this.lock = lock }

        /** Base OkHttp client (timeouts, proxies, certificate pinning). */
        public fun httpClient(client: OkHttpClient): Builder = apply { this.http = client }

        /** Wall clock in epoch milliseconds (tests). */
        public fun clock(clock: () -> Long): Builder = apply { this.clock = clock }

        /** Dispatcher for blocking storage I/O. */
        public fun ioDispatcher(dispatcher: CoroutineDispatcher): Builder = apply { this.io = dispatcher }

        public fun build(): MoonSsoClient {
            val base = http ?: OkHttpClient.Builder()
                .connectTimeout(15, TimeUnit.SECONDS)
                .readTimeout(30, TimeUnit.SECONDS)
                .writeTimeout(30, TimeUnit.SECONDS)
                .build()
            return MoonSsoClient(config, storage, dpopKeyProvider, lock, base, clock, io)
        }
    }
}
