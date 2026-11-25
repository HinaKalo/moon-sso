package cloud.moonl.sso.jwt

import cloud.moonl.sso.AccessTokenClaims
import cloud.moonl.sso.DiscoveryClient
import cloud.moonl.sso.IdTokenClaims
import cloud.moonl.sso.MoonSsoException
import cloud.moonl.sso.internal.SdkJson
import cloud.moonl.sso.internal.requireSuccess
import cloud.moonl.sso.internal.send
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.KeyType
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.SignedJWT
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.longOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import java.security.MessageDigest

/**
 * JWKS cache: keys are kept for one hour; an unknown `kid` forces a refetch at most every 30 seconds.
 */
public class JwksCache internal constructor(
    private val discovery: DiscoveryClient,
    private val http: OkHttpClient,
    private val clock: () -> Long,
) {
    private val mutex = Mutex()

    @Volatile
    private var keys: JWKSet? = null

    @Volatile
    private var fetchedAt = 0L

    private var lastForcedFetch = 0L

    internal suspend fun find(kid: String?, alg: JWSAlgorithm): JWK? {
        val now = clock()
        val current = keys
        if (current != null && now - fetchedAt < TTL) {
            select(current, kid, alg)?.let { return it }
        }
        return mutex.withLock {
            val again = keys
            val t = clock()
            if (again != null && t - fetchedAt < TTL) {
                select(again, kid, alg)?.let { return@withLock it }
                // Unknown kid in a fresh set: refetch, but at most every 30 seconds.
                if (t - lastForcedFetch < FORCED_INTERVAL) return@withLock null
                lastForcedFetch = t
            }
            val fetched = try {
                fetch()
            } catch (e: MoonSsoException) {
                // Keep using a stale set when the JWKS endpoint is unavailable.
                again?.let { return@withLock select(it, kid, alg) } ?: throw e
            }
            keys = fetched
            fetchedAt = t
            select(fetched, kid, alg)
        }
    }

    private suspend fun fetch(): JWKSet {
        val doc = discovery.get()
        val res = http.send(Request.Builder().url(doc.jwksUri).header("Accept", "application/json").get().build()).requireSuccess()
        return try {
            JWKSet.parse(res.body)
        } catch (e: Exception) {
            throw MoonSsoException(MoonSsoException.INVALID_RESPONSE, "malformed JWKS (${e.javaClass.simpleName})", res.code)
        }
    }

    private fun select(set: JWKSet, kid: String?, alg: JWSAlgorithm): JWK? {
        val kty = if (JWSAlgorithm.Family.EC.contains(alg)) KeyType.EC else KeyType.RSA
        val candidates = set.keys.filter { k ->
            k.keyType == kty && (k.keyUse == null || k.keyUse == KeyUse.SIGNATURE) &&
                (k.algorithm == null || k.algorithm == alg)
        }
        return if (kid != null) candidates.firstOrNull { it.keyID == kid } else candidates.singleOrNull()
    }

    private companion object {
        const val TTL = 60 * 60 * 1000L
        const val FORCED_INTERVAL = 30 * 1000L
    }
}

private val ALLOWED_ALGS = setOf(JWSAlgorithm.RS256, JWSAlgorithm.ES256)
private const val SKEW_SECONDS = 60L

internal suspend fun verifySignature(jwt: SignedJWT, jwks: JwksCache, what: String) {
    val alg = jwt.header.algorithm
    if (alg !in ALLOWED_ALGS) throw invalid("$what uses unsupported algorithm ${alg?.name}")
    val jwk = jwks.find(jwt.header.keyID, alg) ?: throw invalid("$what signing key not found")
    val verifier = when (jwk) {
        is RSAKey -> RSASSAVerifier(jwk)
        is ECKey -> ECDSAVerifier(jwk)
        else -> throw invalid("$what signing key has an unsupported type")
    }
    val ok = try {
        jwt.verify(verifier)
    } catch (e: Exception) {
        false
    }
    if (!ok) throw invalid("$what signature is invalid")
}

private fun invalid(msg: String) = MoonSsoException(MoonSsoException.INVALID_RESPONSE, msg)

private fun parse(token: String, what: String): Pair<SignedJWT, JsonObject> = try {
    val jwt = SignedJWT.parse(token)
    jwt to (SdkJson.parseToJsonElement(jwt.payload.toString()) as JsonObject)
} catch (e: Exception) {
    // No cause: parser messages may quote the token.
    throw MoonSsoException(MoonSsoException.INVALID_RESPONSE, "$what is not a valid JWT (${e.javaClass.simpleName})")
}

private fun JsonObject.str(key: String): String? = (this[key] as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull
private fun JsonObject.num(key: String): Long? = (this[key] as? JsonPrimitive)?.longOrNull
private fun JsonObject.audiences(): List<String> = when (val a = this["aud"]) {
    is JsonPrimitive -> listOfNotNull(a.contentOrNull)
    is JsonArray -> a.mapNotNull { (it as? JsonPrimitive)?.contentOrNull }
    else -> emptyList()
}

/** Verifies ID tokens (OpenID Connect Core §3.1.3.7) against the issuer's JWKS. */
public class IdTokenVerifier internal constructor(
    private val issuer: String,
    private val clientId: String,
    private val jwks: JwksCache,
    private val clock: () -> Long,
) {
    /**
     * Verifies signature, `iss`, `aud`, `azp`, `exp`, `iat` (60 s skew), [expectedNonce] when given,
     * and `at_hash` when both the claim and [accessToken] are present.
     */
    public suspend fun verify(idToken: String, expectedNonce: String? = null, accessToken: String? = null): IdTokenClaims {
        val (jwt, claims) = parse(idToken, "id_token")
        verifySignature(jwt, jwks, "id_token")
        val now = clock() / 1000
        if (claims.str("iss") != issuer) throw invalid("id_token iss mismatch")
        val aud = claims.audiences()
        if (clientId !in aud) throw invalid("id_token aud does not contain the client")
        if (aud.size > 1 && claims.str("azp") != clientId) throw invalid("id_token azp mismatch")
        val exp = claims.num("exp") ?: throw invalid("id_token has no exp")
        val iat = claims.num("iat") ?: throw invalid("id_token has no iat")
        if (now > exp + SKEW_SECONDS) throw invalid("id_token expired")
        if (iat > now + SKEW_SECONDS) throw invalid("id_token issued in the future")
        val sub = claims.str("sub")?.takeIf { it.isNotEmpty() } ?: throw invalid("id_token has no sub")
        val nonce = claims.str("nonce")
        if (expectedNonce != null && !constantTimeEquals(nonce, expectedNonce)) throw invalid("id_token nonce mismatch")
        val atHash = claims.str("at_hash")
        if (atHash != null && accessToken != null) {
            if (!constantTimeEquals(atHash, leftHalfHash(accessToken, jwt.header.algorithm))) {
                throw invalid("id_token at_hash mismatch")
            }
        }
        return IdTokenClaims(sub, iat, exp, nonce, claims.str("sid"), claims)
    }
}

/**
 * Local validation of access tokens for resource servers: signature, `typ == at+jwt`, `iss`,
 * `exp`, `nbf` and that `aud` contains [expectedAudience].
 */
public class AccessTokenVerifier internal constructor(
    private val issuer: String,
    private val jwks: JwksCache,
    private val clock: () -> Long,
) {
    public suspend fun verify(accessToken: String, expectedAudience: String): AccessTokenClaims {
        val (jwt, claims) = parse(accessToken, "access token")
        if (jwt.header.type != JOSEObjectType("at+jwt")) throw invalid("access token typ must be at+jwt")
        verifySignature(jwt, jwks, "access token")
        val now = clock() / 1000
        if (claims.str("iss") != issuer) throw invalid("access token iss mismatch")
        val exp = claims.num("exp") ?: throw invalid("access token has no exp")
        if (now >= exp + SKEW_SECONDS) throw invalid("access token expired")
        claims.num("nbf")?.let { if (it > now + SKEW_SECONDS) throw invalid("access token not yet valid") }
        val aud = claims.audiences()
        if (expectedAudience !in aud) throw invalid("access token audience mismatch")
        val sub = claims.str("sub") ?: throw invalid("access token has no sub")
        val scopes = claims.str("scope")?.split(' ')?.filter { it.isNotEmpty() } ?: emptyList()
        return AccessTokenClaims(sub, claims.str("client_id"), scopes, aud, exp, claims)
    }
}

internal fun leftHalfHash(value: String, alg: JWSAlgorithm): String {
    val digest = when (alg) {
        JWSAlgorithm.RS384, JWSAlgorithm.ES384, JWSAlgorithm.PS384 -> "SHA-384"
        JWSAlgorithm.RS512, JWSAlgorithm.ES512, JWSAlgorithm.PS512 -> "SHA-512"
        else -> "SHA-256"
    }
    val h = MessageDigest.getInstance(digest).digest(value.toByteArray(Charsets.US_ASCII))
    return Base64URL.encode(h.copyOf(h.size / 2)).toString()
}

internal fun constantTimeEquals(a: String?, b: String?): Boolean {
    if (a == null || b == null) return false
    return MessageDigest.isEqual(a.toByteArray(Charsets.UTF_8), b.toByteArray(Charsets.UTF_8))
}

/** Reads the `sub` claim without verifying (only for already verified/stored tokens). */
internal fun unverifiedSubject(idToken: String?): String? = try {
    idToken?.let { (SdkJson.parseToJsonElement(SignedJWT.parse(it).payload.toString()) as JsonObject).str("sub") }
} catch (_: Exception) {
    null
}
