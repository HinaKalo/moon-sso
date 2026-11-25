package cloud.moonl.sso

import cloud.moonl.sso.internal.decode
import cloud.moonl.sso.internal.requireSuccess
import cloud.moonl.sso.internal.send
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import okhttp3.OkHttpClient
import okhttp3.Request

/** Subset of `/.well-known/openid-configuration` used by the SDK. */
@Serializable
public data class DiscoveryDocument(
    val issuer: String,
    @SerialName("authorization_endpoint") val authorizationEndpoint: String,
    @SerialName("token_endpoint") val tokenEndpoint: String,
    @SerialName("jwks_uri") val jwksUri: String,
    @SerialName("userinfo_endpoint") val userinfoEndpoint: String? = null,
    @SerialName("revocation_endpoint") val revocationEndpoint: String? = null,
    @SerialName("end_session_endpoint") val endSessionEndpoint: String? = null,
    @SerialName("registration_endpoint") val registrationEndpoint: String? = null,
    @SerialName("introspection_endpoint") val introspectionEndpoint: String? = null,
    @SerialName("authorization_challenge_endpoint") val authorizationChallengeEndpoint: String? = null,
    @SerialName("moon_events_endpoint") val eventsEndpoint: String? = null,
    @SerialName("moon_api_audience") val apiAudience: String? = null,
    @SerialName("authorization_response_iss_parameter_supported") val issParameterSupported: Boolean = false,
    @SerialName("dpop_signing_alg_values_supported") val dpopSigningAlgs: List<String> = emptyList(),
)

/**
 * Fetches and caches the discovery document for one hour. When a refresh fails the expired
 * document keeps being used.
 */
public class DiscoveryClient internal constructor(
    private val issuer: String,
    private val http: OkHttpClient,
    private val clock: () -> Long,
    private val ttlMillis: Long = 60 * 60 * 1000L,
) {
    private val mutex = Mutex()

    @Volatile
    private var cached: DiscoveryDocument? = null

    @Volatile
    private var fetchedAt: Long = 0

    /** Returns the (cached) discovery document. */
    public suspend fun get(): DiscoveryDocument {
        cached?.let { if (clock() - fetchedAt < ttlMillis) return it }
        return mutex.withLock {
            val now = clock()
            cached?.let { if (now - fetchedAt < ttlMillis) return@withLock it }
            try {
                val doc = fetch()
                cached = doc
                fetchedAt = now
                doc
            } catch (e: MoonSsoException) {
                cached ?: throw e
            }
        }
    }

    private suspend fun fetch(): DiscoveryDocument {
        val request = Request.Builder()
            .url("$issuer/.well-known/openid-configuration")
            .header("Accept", "application/json")
            .get()
            .build()
        val doc = http.send(request).requireSuccess().decode<DiscoveryDocument>()
        if (doc.issuer.trimEnd('/') != issuer) {
            throw MoonSsoException(MoonSsoException.INVALID_RESPONSE, "discovery issuer does not match the configured issuer")
        }
        return doc
    }
}
