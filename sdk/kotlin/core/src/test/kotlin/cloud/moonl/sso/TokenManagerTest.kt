package cloud.moonl.sso

import cloud.moonl.sso.internal.SdkJson
import cloud.moonl.sso.storage.InMemorySecureStorage
import cloud.moonl.sso.storage.PersistedState
import com.nimbusds.jwt.SignedJWT
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import okhttp3.Request
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import okhttp3.mockwebserver.SocketPolicy
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Token lifecycle against a scripted server (deterministic retry/expiry behavior). */
class TokenManagerTest {
    private lateinit var server: MockWebServer
    private lateinit var issuer: String
    private val tokenRequests = ConcurrentLinkedQueue<RecordedRequest>()
    private val tokenScript = ConcurrentLinkedQueue<(RecordedRequest) -> MockResponse>()
    private val counter = AtomicInteger()

    @BeforeTest
    fun setUp() {
        server = MockWebServer()
        server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse = when (request.path) {
                "/.well-known/openid-configuration" -> MockResponse().setBody(
                    """{"issuer":"$issuer","authorization_endpoint":"$issuer/oauth/authorize","token_endpoint":"$issuer/oauth/token",
                       "jwks_uri":"$issuer/jwks","revocation_endpoint":"$issuer/oauth/revoke"}""",
                )
                "/oauth/token" -> {
                    tokenRequests.add(request)
                    (tokenScript.poll() ?: { ok() })(request)
                }
                "/oauth/revoke" -> MockResponse().setResponseCode(200)
                "/api/ping" -> if (request.getHeader("Authorization") == "Bearer at-0") {
                    MockResponse().setResponseCode(401).setBody("""{"error":"invalid_token"}""")
                } else {
                    MockResponse().setBody("pong ${request.getHeader("Authorization")}")
                }
                else -> MockResponse().setResponseCode(404)
            }
        }
        server.start(java.net.InetAddress.getByName("127.0.0.1"), 0)
        issuer = "http://127.0.0.1:${server.port}"
    }

    @AfterTest
    fun tearDown() = server.shutdown()

    private fun ok(): MockResponse {
        val n = counter.incrementAndGet()
        Thread.sleep(50) // widen the race window for concurrent callers
        return MockResponse().setHeader("DPoP-Nonce", "nonce-$n")
            .setBody("""{"access_token":"at-$n","token_type":"Bearer","expires_in":600,"refresh_token":"rt-$n","scope":"openid profile"}""")
    }

    private fun json(code: Int, body: String) = MockResponse().setResponseCode(code).setBody(body)

    private fun client(
        storage: InMemorySecureStorage,
        expiresIn: Long = 600,
        issuedAgo: Long = 0,
        clock: () -> Long = System::currentTimeMillis,
        dpop: Boolean = true,
    ): MoonSsoClient {
        val now = clock() / 1000
        val state = PersistedState(issuer = issuer, clientId = "app").withTokens(
            TokenSet("at-0", "Bearer", "rt-0", null, "openid profile", now - issuedAgo, now - issuedAgo + expiresIn),
            "sub-1",
        )
        storage.write(SdkJson.encodeToString(PersistedState.serializer(), state))
        val config = MoonSsoConfig(issuer, "app", useDpop = dpop, autoRefresh = false, logger = MoonSsoLogger.None)
        return MoonSsoClient.Builder(config).storage(storage).clock(clock).build()
    }

    @Test
    fun `fresh token is used without refreshing`() = runBlocking {
        val c = client(InMemorySecureStorage())
        assertEquals("at-0", c.accessToken())
        assertEquals(0, tokenRequests.size)
    }

    @Test
    fun `token past 75 percent of its lifetime is refreshed before use and rotation is persisted`() = runBlocking {
        val storage = InMemorySecureStorage()
        val c = client(storage, expiresIn = 600, issuedAgo = 460)
        assertEquals("at-1", c.accessToken())
        val req = tokenRequests.single()
        val form = req.body.readUtf8()
        assertTrue("grant_type=refresh_token" in form && "refresh_token=rt-0" in form && "client_id=app" in form, form)
        val stored = SdkJson.decodeFromString(PersistedState.serializer(), storage.read()!!)
        assertEquals("rt-1", stored.refreshToken)
        assertEquals("at-1", stored.accessToken)
    }

    @Test
    fun `token at 70 percent of its lifetime is still used`() = runBlocking {
        val c = client(InMemorySecureStorage(), expiresIn = 600, issuedAgo = 420)
        assertEquals("at-0", c.accessToken())
    }

    @Test
    fun `concurrent refreshes share one request`() = runBlocking {
        val c = client(InMemorySecureStorage())
        c.initialize()
        val results = List(50) { async(Dispatchers.Default) { c.tokenManager.refresh().accessToken } }.awaitAll()
        assertEquals(1, tokenRequests.size)
        assertEquals(setOf("at-1"), results.toSet())
    }

    @Test
    fun `retries once on 503 and on a dropped connection`() = runBlocking {
        tokenScript.add { json(503, """{"error":"temporarily_unavailable"}""") }
        val c = client(InMemorySecureStorage())
        c.initialize()
        assertEquals("at-1", c.tokenManager.refresh().accessToken)
        assertEquals(2, tokenRequests.size)

        tokenRequests.clear()
        tokenScript.add { MockResponse().setSocketPolicy(SocketPolicy.DISCONNECT_AFTER_REQUEST) }
        assertEquals("at-2", c.tokenManager.refresh().accessToken)
        assertEquals(2, tokenRequests.size)
        // Each attempt carries a fresh DPoP proof.
        val jtis = tokenRequests.map { SignedJWT.parse(it.getHeader("DPoP")).jwtClaimsSet.jwtid }
        assertEquals(2, jtis.toSet().size)
    }

    @Test
    fun `second 502 is reported and the session is kept`() = runBlocking {
        tokenScript.add { json(502, "bad gateway") }
        tokenScript.add { json(502, "bad gateway") }
        val c = client(InMemorySecureStorage())
        c.initialize()
        val e = assertFailsWith<MoonSsoException> { c.tokenManager.refresh() }
        assertEquals(502, e.httpStatus)
        assertTrue(e.isTransient)
        assertIs<AuthState.SignedIn>(c.authState.value)
        assertEquals("at-0", c.tokens.value?.accessToken)
    }

    @Test
    fun `use_dpop_nonce is retried with the new nonce`() = runBlocking {
        tokenScript.add {
            MockResponse().setResponseCode(400).setHeader("DPoP-Nonce", "server-nonce")
                .setBody("""{"error":"use_dpop_nonce","error_description":"nonce required"}""")
        }
        val c = client(InMemorySecureStorage())
        c.initialize()
        assertEquals("at-1", c.tokenManager.refresh().accessToken)
        val proofs = tokenRequests.map { SignedJWT.parse(it.getHeader("DPoP")).jwtClaimsSet }
        assertNull(proofs[0].getClaim("nonce"))
        assertEquals("server-nonce", proofs[1].getStringClaim("nonce"))
        assertEquals("$issuer/oauth/token", proofs[1].getStringClaim("htu"))
    }

    @Test
    fun `invalid_grant ends the session and emits SessionExpired`() = runBlocking {
        tokenScript.add { json(400, """{"error":"invalid_grant","error_description":"refresh token revoked"}""") }
        val storage = InMemorySecureStorage()
        val c = client(storage)
        c.initialize()
        val event = async { withTimeout(5_000) { c.sessionExpired.first() } }
        kotlinx.coroutines.yield()
        assertFailsWith<SessionExpiredException> { c.tokenManager.refresh() }
        assertEquals("refresh token revoked", event.await().reason)
        assertIs<AuthState.SessionExpired>(c.authState.value)
        val stored = SdkJson.decodeFromString(PersistedState.serializer(), storage.read()!!)
        assertNull(stored.refreshToken)
        assertNotNull(stored.dpopKey, "the DPoP key outlives the session")
        val e = assertFailsWith<MoonSsoException> { c.accessToken() }
        assertEquals(MoonSsoException.LOGIN_REQUIRED, e.error)
    }

    @Test
    fun `invalid_client is not retried and does not end the session`() = runBlocking {
        tokenScript.add { json(401, """{"error":"invalid_client"}""") }
        val c = client(InMemorySecureStorage())
        c.initialize()
        val e = assertFailsWith<MoonSsoException> { c.tokenManager.refresh() }
        assertEquals("invalid_client", e.error)
        assertEquals(1, tokenRequests.size)
        assertIs<AuthState.SignedIn>(c.authState.value)
    }

    @Test
    fun `interceptor attaches the token and the authenticator refreshes once on 401`() = runBlocking {
        val c = client(InMemorySecureStorage())
        c.initialize()
        val body = kotlinx.coroutines.withContext(Dispatchers.IO) {
            c.httpClient.newCall(Request.Builder().url("$issuer/api/ping").build()).execute().use { it.body!!.string() }
        }
        assertEquals("pong Bearer at-1", body)
        assertEquals(1, tokenRequests.size)
        // Token is never sent to foreign hosts.
        val foreign = server.url("/api/ping").newBuilder().host("localhost").build()
        val r = kotlinx.coroutines.withContext(Dispatchers.IO) {
            c.httpClient.newCall(Request.Builder().url(foreign).build()).execute().use { it.body!!.string() }
        }
        assertEquals("pong null", r)
    }

    @Test
    fun `sign out clears tokens and revokes the refresh token`() = runBlocking {
        val c = client(InMemorySecureStorage())
        c.initialize()
        c.signOut()
        assertIs<AuthState.SignedOut>(c.authState.value)
        val revoke = server.takeRequestMatching("/oauth/revoke")
        assertTrue("token=rt-0" in revoke.body.readUtf8())
    }

    @Test
    fun `background refresh happens at 75 percent of the lifetime`() = runBlocking {
        val storage = InMemorySecureStorage()
        val now = System.currentTimeMillis() / 1000
        val state = PersistedState(issuer = issuer, clientId = "app").withTokens(
            TokenSet("at-0", "Bearer", "rt-0", null, "openid", now, now + 4), "sub-1",
        )
        storage.write(SdkJson.encodeToString(PersistedState.serializer(), state))
        val c = MoonSsoClient.Builder(MoonSsoConfig(issuer, "app", autoRefresh = true, logger = MoonSsoLogger.None))
            .storage(storage).build()
        c.initialize()
        val refreshed = withTimeout(10_000) { c.tokens.first { it?.accessToken == "at-1" } }
        assertNotNull(refreshed)
        c.close()
    }

    private fun MockWebServer.takeRequestMatching(path: String): RecordedRequest {
        while (true) {
            val r = takeRequest(5, java.util.concurrent.TimeUnit.SECONDS) ?: error("no request to $path")
            if (r.path == path) return r
        }
    }
}
