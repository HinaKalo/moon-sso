package cloud.moonl.sso

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class PkceTest {
    @Test
    fun `RFC 7636 appendix B test vector`() {
        val pkce = Pkce.fromVerifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
        assertEquals("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", pkce.codeChallenge)
        assertEquals("S256", pkce.codeChallengeMethod)
    }

    @Test
    fun `generated verifier is 43 url-safe characters with 256 bits of entropy`() {
        val seen = HashSet<String>()
        repeat(200) {
            val p = Pkce.generate()
            assertEquals(43, p.codeVerifier.length)
            assertTrue(p.codeVerifier.all { it.isLetterOrDigit() || it == '-' || it == '_' }, p.codeVerifier)
            assertEquals(Pkce.challengeFor(p.codeVerifier), p.codeChallenge)
            assertTrue(seen.add(p.codeVerifier))
        }
    }

    @Test
    fun `rejects verifiers outside RFC limits`() {
        assertFailsWith<IllegalArgumentException> { Pkce.fromVerifier("short") }
        assertFailsWith<IllegalArgumentException> { Pkce.fromVerifier("a".repeat(129)) }
        assertFailsWith<IllegalArgumentException> { Pkce.fromVerifier("a".repeat(42) + "+") }
    }

    @Test
    fun `random tokens carry at least 128 bits`() {
        val t = SecureTokens.token(16)
        assertEquals(22, t.length)
        assertNotEquals(t, SecureTokens.token(16))
    }

    @Test
    fun `toString never reveals the verifier`() {
        val p = Pkce.generate()
        assertTrue(p.codeVerifier !in p.toString())
    }
}
