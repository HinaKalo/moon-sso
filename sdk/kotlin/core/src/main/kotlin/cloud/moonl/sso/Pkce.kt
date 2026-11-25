package cloud.moonl.sso

import com.nimbusds.jose.util.Base64URL
import java.security.MessageDigest
import java.security.SecureRandom

/** PKCE (RFC 7636) S256 verifier/challenge pair. The verifier is 43 characters of base64url (256 bits). */
public class Pkce private constructor(
    public val codeVerifier: String,
    public val codeChallenge: String,
) {
    public val codeChallengeMethod: String get() = "S256"

    override fun toString(): String = "Pkce(method=S256)"

    public companion object {
        /** Generates a new random verifier. */
        public fun generate(): Pkce = fromVerifier(SecureTokens.token(32))

        /** Rebuilds a pair from a stored verifier. */
        public fun fromVerifier(verifier: String): Pkce {
            require(verifier.length in 43..128) { "code_verifier must be 43-128 characters" }
            require(verifier.all { it.isLetterOrDigit() && it.code < 128 || it in "-._~" }) { "code_verifier contains invalid characters" }
            return Pkce(verifier, challengeFor(verifier))
        }

        /** `BASE64URL(SHA256(ASCII(verifier)))`. */
        public fun challengeFor(verifier: String): String =
            Base64URL.encode(MessageDigest.getInstance("SHA-256").digest(verifier.toByteArray(Charsets.US_ASCII))).toString()
    }
}

/** Cryptographically secure random values. */
public object SecureTokens {
    private val rng = SecureRandom()

    /** Base64url (no padding) of [bytes] random bytes. 16 bytes = 128 bits. */
    public fun token(bytes: Int = 32): String {
        val b = ByteArray(bytes)
        rng.nextBytes(b)
        return Base64URL.encode(b).toString()
    }

    internal fun nextLong(from: Long, until: Long): Long {
        val span = until - from
        return from + Math.floorMod(rng.nextLong(), span)
    }
}
