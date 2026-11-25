package cloud.moonl.sso.it

import cloud.moonl.sso.MoonSsoClient
import cloud.moonl.sso.MoonSsoConfig
import cloud.moonl.sso.MoonSsoLogger
import cloud.moonl.sso.storage.CrossProcessLock
import cloud.moonl.sso.storage.InMemorySecureStorage
import cloud.moonl.sso.storage.SecureStorage
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.FormBody
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.Interceptor
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.junit.jupiter.api.Assumptions.assumeTrue
import java.security.SecureRandom
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.TimeUnit

/** Helpers for the shared local testbed (docs/sdk-spec.md §8). */
object Testbed {
    val issuer: String = (System.getProperty("moonsso.testbed") ?: "http://127.0.0.1:18601").trimEnd('/')
    val ALL_SCOPES = listOf("openid", "profile", "offline_access", "profile:write", "password:write")

    private val http = OkHttpClient.Builder().callTimeout(30, TimeUnit.SECONDS).build()
    private val json = Json { ignoreUnknownKeys = true }
    private val rng = SecureRandom()

    private val reachable: Boolean by lazy {
        try {
            OkHttpClient.Builder().callTimeout(3, TimeUnit.SECONDS).build()
                .newCall(Request.Builder().url("$issuer/.well-known/openid-configuration").build()).execute()
                .use { it.isSuccessful }
        } catch (e: Exception) {
            false
        }
    }

    fun requireTestbed() = assumeTrue(reachable, "testbed $issuer is not reachable")

    fun randomName(prefix: String = "t_"): String {
        val alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
        return prefix + (1..8).map { alphabet[rng.nextInt(alphabet.length)] }.joinToString("")
    }

    fun randomPassword(): String = "Pw-" + randomName("") + "-" + randomName("") + "!9"

    private fun post(path: String, body: okhttp3.RequestBody): JsonObject =
        http.newCall(Request.Builder().url("$issuer$path").post(body).build()).execute().use { r ->
            val text = r.body!!.string()
            check(r.isSuccessful) { "POST $path failed: HTTP ${r.code} $text" }
            json.parseToJsonElement(text).jsonObject
        }

    private fun postJson(path: String, body: String) = post(path, body.toRequestBody("application/json".toMediaType()))

    /** Creates a fresh user; returns (username, password). */
    fun createUser(): Pair<String, String> {
        val u = randomName()
        val p = randomPassword()
        postJson("/__test/users", """{"username":"$u","password":"$p"}""")
        return u to p
    }

    fun totp(secret: String): String = post("/__test/totp?secret=$secret", ByteArray(0).toRequestBody(null))["code"]!!.jsonPrimitive.content

    fun setDisplayName(username: String, name: String) {
        postJson("/__test/users/$username/profile", """{"display_name":"$name"}""")
    }

    fun initialAccessToken(): String = post("/__test/iat", ByteArray(0).toRequestBody(null))["token"]!!.jsonPrimitive.content

    fun trustClient(clientId: String) {
        post("/__test/clients/$clientId/trust", ByteArray(0).toRequestBody(null))
    }

    /** Completes an authorization request like a browser would; returns the redirect URL. */
    fun authorize(authorizationUrl: String, username: String, password: String): String {
        val url = authorizationUrl.toHttpUrl()
        val form = FormBody.Builder().apply {
            for (i in 0 until url.querySize) add(url.queryParameterName(i), url.queryParameterValue(i) ?: "")
            add("username", username)
            add("password", password)
        }.build()
        return post("/__test/authorize", form)["redirect"]!!.jsonPrimitive.content
    }

    /** Records (path, status, error) of every network response of a client. */
    class Recorder : Interceptor {
        data class Entry(val path: String, val status: Int, val error: String?, val grantType: String?)

        val entries = ConcurrentLinkedQueue<Entry>()

        override fun intercept(chain: Interceptor.Chain): okhttp3.Response {
            val req = chain.request()
            val grant = (req.body as? FormBody)?.let { f -> (0 until f.size).firstOrNull { f.name(it) == "grant_type" }?.let { f.value(it) } }
            val res = chain.proceed(req)
            val err = if (res.code >= 400) {
                Regex("\"error\"\\s*:\\s*\"([^\"]+)\"").find(res.peekBody(4096).string())?.groupValues?.get(1)
            } else {
                null
            }
            entries.add(Entry(req.url.encodedPath, res.code, err, grant))
            return res
        }

        fun count(path: String, error: String? = null, grant: String? = null, status: Int? = null) =
            entries.count {
                it.path == path && (error == null || it.error == error) && (grant == null || it.grantType == grant) &&
                    (status == null || it.status == status)
            }

        fun clear() = entries.clear()
    }

    /** In-JVM stand-in for a cross-process lock shared by several clients. */
    class SharedLock : CrossProcessLock {
        private val mutex = Mutex()
        override suspend fun <T> withLock(block: suspend () -> T): T = mutex.withLock { block() }
    }

    fun client(
        clientId: String = "test-native",
        scopes: List<String> = ALL_SCOPES,
        useDpop: Boolean = true,
        storage: SecureStorage = InMemorySecureStorage(),
        recorder: Recorder? = null,
        lock: CrossProcessLock? = null,
        autoRefresh: Boolean = false,
    ): MoonSsoClient {
        val base = OkHttpClient.Builder().apply { recorder?.let { addNetworkInterceptor(it) } }.build()
        val config = MoonSsoConfig(issuer, clientId, scopes = scopes, useDpop = useDpop, autoRefresh = autoRefresh, logger = MoonSsoLogger.None)
        return MoonSsoClient.Builder(config).storage(storage).httpClient(base).apply { lock?.let { crossProcessLock(it) } }.build()
    }
}
