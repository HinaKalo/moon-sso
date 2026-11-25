package cloud.moonl.sso.dpop

import cloud.moonl.sso.SecureTokens
import cloud.moonl.sso.storage.SessionStore
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import java.security.PrivateKey
import java.security.interfaces.ECPublicKey
import java.util.Date

/** A P-256 key pair used for DPoP proofs. The private key may be non-extractable (Android Keystore). */
public class DpopKey(
    public val publicKey: ECPublicKey,
    public val privateKey: PrivateKey,
) {
    internal val publicJwk: ECKey = ECKey.Builder(Curve.P_256, publicKey).build()

    /** base64url SHA-256 JWK thumbprint (RFC 7638), used as `dpop_jkt`. */
    public val thumbprint: String = publicJwk.computeThumbprint("SHA-256").toString()

    override fun toString(): String = "DpopKey(jkt=$thumbprint)"
}

/** Supplies the installation's long-lived DPoP key. */
public interface DpopKeyProvider {
    /** Returns the key, creating and persisting it on first use. */
    public suspend fun key(): DpopKey
}

/** Keeps a key only in memory (tests, ephemeral processes). */
public class InMemoryDpopKeyProvider : DpopKeyProvider {
    private val key: DpopKey by lazy { generateSoftwareKey().second }

    override suspend fun key(): DpopKey = key
}

internal fun generateSoftwareKey(): Pair<ECKey, DpopKey> {
    val jwk = ECKeyGenerator(Curve.P_256).generate()
    return jwk to DpopKey(jwk.toECPublicKey(), jwk.toECPrivateKey())
}

internal fun parseSoftwareKey(json: String): DpopKey {
    val jwk = ECKey.parse(json)
    require(jwk.curve == Curve.P_256 && jwk.isPrivate) { "stored DPoP key is not a private P-256 key" }
    return DpopKey(jwk.toECPublicKey(), jwk.toECPrivateKey())
}

/**
 * Stores an exportable software key as a private JWK inside the session JSON of the secure
 * storage (desktop rule: the key may be exportable but must live in the OS secure storage).
 * Generation runs inside a storage transaction so that processes sharing the storage converge on
 * one key.
 */
internal class StoredDpopKeyProvider(private val store: SessionStore) : DpopKeyProvider {
    @Volatile
    private var cache: Pair<String, DpopKey>? = null

    override suspend fun key(): DpopKey {
        store.state.dpopKey?.let { return fromJson(it) }
        val json = store.transaction { tx ->
            tx.current.dpopKey ?: run {
                val (jwk, _) = generateSoftwareKey()
                val s = jwk.toJSONString()
                tx.write(tx.current.copy(dpopKey = s))
                s
            }
        }
        return fromJson(json)
    }

    private fun fromJson(json: String): DpopKey {
        cache?.let { (j, k) -> if (j == json) return k }
        val k = parseSoftwareKey(json)
        cache = json to k
        return k
    }
}

/** Builds DPoP proofs and tracks the latest server nonce. */
internal class DpopProofs(private val keys: DpopKeyProvider, private val clock: () -> Long) {
    @Volatile
    var nonce: String? = null

    suspend fun key(): DpopKey = keys.key()

    /** Proof for [method] on [url] (query and fragment are removed for `htu`). */
    suspend fun proof(method: String, url: String): String {
        val key = keys.key()
        val htu = url.substringBefore('#').substringBefore('?')
        val header = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectType("dpop+jwt"))
            .jwk(key.publicJwk)
            .build()
        val claims = JWTClaimsSet.Builder()
            .jwtID(SecureTokens.token(16))
            .claim("htm", method)
            .claim("htu", htu)
            .issueTime(Date((clock() / 1000) * 1000))
            .apply { nonce?.let { claim("nonce", it) } }
            .build()
        val jwt = SignedJWT(header, claims)
        jwt.sign(ECDSASigner(key.privateKey, Curve.P_256))
        return jwt.serialize()
    }

    fun observe(headers: okhttp3.Headers) {
        headers["DPoP-Nonce"]?.takeIf { it.isNotBlank() && it.length <= 512 }?.let { nonce = it }
    }
}
