package cloud.moonl.sso.desktop

import cloud.moonl.sso.AuthState
import cloud.moonl.sso.MoonSsoClient
import cloud.moonl.sso.MoonSsoConfig
import cloud.moonl.sso.MoonSsoException
import cloud.moonl.sso.MoonSsoLogger
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.FormBody
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import okhttp3.Request
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.io.TempDir
import java.net.URI
import java.nio.file.Path
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

class DesktopIntegrationTest {
    private val issuer = (System.getProperty("moonsso.testbed") ?: "http://127.0.0.1:18601").trimEnd('/')
    private val http = OkHttpClient.Builder().callTimeout(30, TimeUnit.SECONDS).followRedirects(false).build()
    private val scopes = listOf("openid", "profile", "offline_access")

    @TempDir
    lateinit var dir: Path

    @BeforeEach
    fun requireTestbed() {
        val up = try {
            http.newCall(Request.Builder().url("$issuer/.well-known/openid-configuration").build()).execute().use { it.isSuccessful }
        } catch (e: Exception) {
            false
        }
        assumeTrue(up, "testbed $issuer is not reachable")
    }

    /** Stands in for the user in the browser: POST /__test/authorize with the authorization request. */
    private fun browserLogin(authorizationUrl: String, username: String = "alice", password: String = "Wonderland-Pass-1"): String {
        val url = authorizationUrl.toHttpUrl()
        val form = FormBody.Builder().apply {
            for (i in 0 until url.querySize) add(url.queryParameterName(i), url.queryParameterValue(i) ?: "")
            add("username", username)
            add("password", password)
        }.build()
        val text = http.newCall(Request.Builder().url("$issuer/__test/authorize").post(form).build()).execute().use {
            val body = it.body!!.string()
            check(it.isSuccessful) { "authorize failed: ${it.code} $body" }
            body
        }
        return Json.parseToJsonElement(text).jsonObject["redirect"]!!.jsonPrimitive.content
    }

    /** Records "grant_type:status" of token endpoint calls. */
    private class Recorder : Interceptor {
        val grants = ConcurrentLinkedQueue<String>()
        override fun intercept(chain: Interceptor.Chain): okhttp3.Response {
            val body = chain.request().body as? FormBody
            val grant = body?.let { f -> (0 until f.size).firstOrNull { f.name(it) == "grant_type" }?.let { f.value(it) } }
            val response = chain.proceed(chain.request())
            grant?.let { grants.add("$it:${response.code}") }
            return response
        }
    }

    private fun config(clientId: String = "test-native") =
        MoonSsoConfig(issuer, clientId, scopes = scopes, autoRefresh = false, logger = MoonSsoLogger.None)

    @Test
    fun `authorization code from the browser is exchanged through the desktop code path`() = runBlocking {
        val client = MoonSsoDesktop.create(config(), "it-code", directory = dir)
        val redirect = "http://127.0.0.1/callback"
        val pending = client.createAuthorizationRequest(redirect)
        val url = pending.authorizationUrl.toHttpUrl()
        assertEquals("S256", url.queryParameter("code_challenge_method"))
        assertNotNull(url.queryParameter("dpop_jkt"))
        assertNotNull(url.queryParameter("nonce"))
        val callback = browserLogin(pending.authorizationUrl)
        assertTrue(callback.startsWith("$redirect?"), callback)
        assertEquals(issuer, callback.toHttpUrl().queryParameter("iss"))

        // A forged callback with another state is rejected before any code exchange.
        val forged = callback.replace("state=", "state=x")
        assertEquals(MoonSsoException.STATE_MISMATCH, assertFailsWith<MoonSsoException> { client.completeAuthorization(pending, forged) }.error)

        val tokens = client.completeAuthorization(pending, callback)
        assertNotNull(tokens.refreshToken)
        assertIs<AuthState.SignedIn>(client.authState.value)
        assertEquals("alice", client.account.getMe().preferredUsername)
        client.close()

        // The session survives a restart (secure storage).
        val again = MoonSsoDesktop.create(config(), "it-code", directory = dir)
        again.initialize()
        assertEquals(tokens.refreshToken, again.tokens.value?.refreshToken)
        assertEquals("alice", again.account.getMe().preferredUsername)
        again.signOut()
        again.close()
    }

    @Test
    fun `wrong iss in the authorization response is rejected`() = runBlocking {
        val client = MoonSsoDesktop.create(config(), "it-iss", directory = dir)
        val pending = client.createAuthorizationRequest("http://127.0.0.1/callback")
        val callback = browserLogin(pending.authorizationUrl)
        val bad = callback.toHttpUrl().newBuilder().setQueryParameter("iss", "https://evil.example").build().toString()
        val e = assertFailsWith<MoonSsoException> { client.completeAuthorization(pending, bad) }
        assertEquals(MoonSsoException.INVALID_RESPONSE, e.error)
        client.close()
    }

    @Test
    fun `full loopback browser login on a random port`() = runBlocking {
        val client = MoonSsoDesktop.create(config("test-native-dpop"), "it-loopback", directory = dir)
        var page = ""
        val launcher = BrowserLauncher { uri: URI ->
            val redirect = browserLogin(uri.toString())
            assertTrue(redirect.startsWith("http://127.0.0.1:") && "/callback?" in redirect, redirect)
            // The "browser" follows the redirect to the SDK's loopback listener.
            page = http.newCall(Request.Builder().url(redirect).build()).execute().use { it.body!!.string() }
        }
        val tokens = DesktopLogin(client, launcher).login()
        assertTrue("登录完成" in page, page)
        assertNotNull(tokens.idToken)
        assertEquals("alice", client.account.getMe().preferredUsername)
        client.close()
    }

    @Test
    fun `loopback login times out`() = runBlocking {
        val client = MoonSsoDesktop.create(config(), "it-timeout", directory = dir)
        val e = assertFailsWith<MoonSsoException> { DesktopLogin(client, { }, timeout = 1.seconds).login() }
        assertEquals(MoonSsoException.TIMEOUT, e.error)
        client.close()
    }

    @Test
    fun `processes sharing the desktop storage refresh once under the file lock`() = runBlocking {
        val rec = Recorder()
        val base = OkHttpClient.Builder().addNetworkInterceptor(rec).build()
        val a = MoonSsoDesktop.create(config(), "it-shared", base, dir)
        a.signInWithPassword("alice", "Wonderland-Pass-1")
        val clients = listOf(a) + List(3) { MoonSsoDesktop.create(config(), "it-shared", base, dir).also { it.initialize() } }
        rec.grants.clear()
        val results = clients.map { c -> async(Dispatchers.Default) { c.tokenManager.refresh() } }.awaitAll()
        // Exactly one successful refresh; the others adopted it from the shared storage after taking the
        // file lock. (A client that never talked to the server may first get one use_dpop_nonce answer.)
        assertEquals(listOf("refresh_token:200"), rec.grants.filter { it.endsWith(":200") }, rec.grants.toString())
        assertEquals(1, results.map { it.refreshToken }.toSet().size)
        for (c in clients) {
            assertEquals("alice", c.account.getMe().preferredUsername)
            c.close()
        }
    }
}
