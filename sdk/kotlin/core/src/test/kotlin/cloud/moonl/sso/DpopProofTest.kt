package cloud.moonl.sso

import cloud.moonl.sso.dpop.DpopProofs
import cloud.moonl.sso.dpop.InMemoryDpopKeyProvider
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jwt.SignedJWT
import kotlinx.coroutines.test.runTest
import okhttp3.Headers.Companion.headersOf
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DpopProofTest {
    private val now = 1_800_000_000_123L

    @Test
    fun `proof has the RFC 9449 shape and verifies with the embedded key`() = runTest {
        val keys = InMemoryDpopKeyProvider()
        val dpop = DpopProofs(keys) { now }
        val proof = SignedJWT.parse(dpop.proof("POST", "https://sso.example/oauth/token?x=1#frag"))

        val h = proof.header
        assertEquals(JWSAlgorithm.ES256, h.algorithm)
        assertEquals(JOSEObjectType("dpop+jwt"), h.type)
        val jwk = h.jwk as ECKey
        assertFalse(jwk.isPrivate)
        assertEquals(setOf("kty", "crv", "x", "y"), jwk.toJSONObject().keys)
        assertEquals("P-256", jwk.toJSONObject()["crv"])
        assertNull(h.keyID)
        assertTrue(proof.verify(ECDSAVerifier(jwk)))

        val c = proof.jwtClaimsSet
        assertEquals("POST", c.getStringClaim("htm"))
        assertEquals("https://sso.example/oauth/token", c.getStringClaim("htu"))
        assertEquals(now / 1000, c.issueTime.time / 1000)
        assertTrue(c.jwtid.length >= 22)
        assertNull(c.getClaim("nonce"))
        assertEquals(setOf("jti", "htm", "htu", "iat"), c.claims.keys)

        // Thumbprint used as dpop_jkt.
        assertEquals(jwk.computeThumbprint("SHA-256").toString(), keys.key().thumbprint)
        assertEquals(43, keys.key().thumbprint.length)
    }

    @Test
    fun `latest server nonce is included and jti is unique`() = runTest {
        val dpop = DpopProofs(InMemoryDpopKeyProvider()) { now }
        dpop.observe(headersOf("DPoP-Nonce", "n-1"))
        dpop.observe(headersOf("Other", "x"))
        val a = SignedJWT.parse(dpop.proof("POST", "https://sso.example/oauth/token")).jwtClaimsSet
        dpop.observe(headersOf("DPoP-Nonce", "n-2"))
        val b = SignedJWT.parse(dpop.proof("POST", "https://sso.example/oauth/token")).jwtClaimsSet
        assertEquals("n-1", a.getStringClaim("nonce"))
        assertEquals("n-2", b.getStringClaim("nonce"))
        assertNotEquals(a.jwtid, b.jwtid)
    }
}
