package cloud.moonl.sso.it

import cloud.moonl.sso.AuthState
import cloud.moonl.sso.ClientMetadata
import cloud.moonl.sso.DynamicClientRegistration
import cloud.moonl.sso.MoonSsoClient
import cloud.moonl.sso.MoonSsoException
import cloud.moonl.sso.OtpRequiredException
import cloud.moonl.sso.SessionExpiredException
import cloud.moonl.sso.TokenSet
import cloud.moonl.sso.UserEvent
import cloud.moonl.sso.sse.EventStreamState
import cloud.moonl.sso.storage.InMemorySecureStorage
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.yield
import okhttp3.FormBody
import okhttp3.OkHttpClient
import okhttp3.Request
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.BeforeEach
import java.awt.image.BufferedImage
import java.io.ByteArrayOutputStream
import javax.imageio.ImageIO
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** End-to-end tests against the shared testbed (http://127.0.0.1:18601). */
class TestbedIntegrationTest {
    private val bobSecret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"

    @BeforeEach
    fun requireTestbed() = Testbed.requireTestbed()

    private suspend fun signedInClient(
        username: String,
        password: String,
        clientId: String = "test-native",
        useDpop: Boolean = true,
        recorder: Testbed.Recorder? = null,
    ): MoonSsoClient {
        val c = Testbed.client(clientId = clientId, useDpop = useDpop, recorder = recorder)
        c.signInWithPassword(username, password)
        return c
    }

    @Test
    fun `alice signs in with the first-party challenge on test-native (with and without DPoP)`() = runBlocking {
        for (dpop in listOf(false, true)) {
            val c = Testbed.client(useDpop = dpop)
            c.initialize()
            assertEquals(AuthState.SignedOut, c.authState.value)
            val tokens = c.signInWithPassword("alice", "Wonderland-Pass-1")
            assertNotNull(tokens.refreshToken)
            assertNotNull(tokens.idToken)
            assertTrue("openid" in tokens.scopes)
            val state = assertIs<AuthState.SignedIn>(c.authState.value)
            val claims = assertNotNull(c.idTokenClaims())
            assertEquals(claims.subject, state.subject)
            val me = c.account.getMe()
            assertEquals("alice", me.preferredUsername)
            assertEquals(claims.subject, me.sub)
            assertEquals(me, c.profile.value)
            // Access token is a valid at+jwt for the client.
            val at = c.accessTokenVerifier.verify(c.accessToken(), "test-native")
            assertEquals(me.sub, at.subject)
            c.signOut()
            assertEquals(AuthState.SignedOut, c.authState.value)
            c.close()
        }
    }

    @Test
    fun `wrong password is access_denied and keeps the client signed out`() = runBlocking {
        val (user, _) = Testbed.createUser()
        val c = Testbed.client()
        val e = assertFailsWith<MoonSsoException> { c.signInWithPassword(user, "Wrong-Password-1") }
        assertEquals("access_denied", e.error)
        assertEquals(403, e.httpStatus)
        assertEquals(AuthState.SignedOut, c.authState.value)
    }

    @Test
    fun `bob needs a TOTP code as second step`() = runBlocking {
        val c = Testbed.client()
        val challenge = assertFailsWith<OtpRequiredException> { c.signInWithPassword("bob", "Builder-Pass-22") }.challenge
        assertEquals("otp", challenge.required)
        // Other SDK suites use bob concurrently and each TOTP step is accepted once; wait for a new step when taken.
        var tokens: TokenSet? = null
        for (attempt in 1..6) {
            try {
                tokens = c.submitOtp(challenge, Testbed.totp(bobSecret))
                break
            } catch (e: OtpRequiredException) {
                delay(31_000L - System.currentTimeMillis() % 30_000L)
            } catch (e: MoonSsoException) {
                if (e.httpStatus != 429) throw e
                delay(2_000)
            }
        }
        assertNotNull(tokens, "OTP step did not succeed")
        val me = c.account.getMe()
        assertEquals("bob", me.preferredUsername)
        assertEquals(true, me.totpEnabled)
        val amr = c.idTokenClaims()!!.claims["amr"].toString()
        assertTrue("otp" in amr, amr)
    }

    @Test
    fun `DPoP-required client uses server nonces and binds the refresh token`() = runBlocking {
        val rec = Testbed.Recorder()
        val c = signedInClient("alice", "Wonderland-Pass-1", clientId = "test-native-dpop", recorder = rec)
        // The first proof had no nonce: the server asked for one and the SDK retried immediately.
        assertTrue(rec.count("/oauth/authorize-challenge", error = "use_dpop_nonce") >= 1, rec.entries.toString())
        assertEquals(1, rec.count("/oauth/token", grant = "authorization_code"))
        val first = c.tokens.value!!
        val second = c.tokenManager.refresh()
        assertNotEquals(first.refreshToken, second.refreshToken)
        assertEquals("alice", c.account.getMe().preferredUsername)
        assertEquals(0, rec.entries.count { it.error == "invalid_dpop_proof" })

        // Without DPoP the client is rejected.
        val plain = Testbed.client(clientId = "test-native-dpop", useDpop = false)
        val e = assertFailsWith<MoonSsoException> { plain.signInWithPassword("alice", "Wonderland-Pass-1") }
        assertEquals("invalid_dpop_proof", e.error)
    }

    @Test
    fun `refresh rotates and concurrent refreshes converge on one request`() = runBlocking {
        val rec = Testbed.Recorder()
        val c = signedInClient("alice", "Wonderland-Pass-1", recorder = rec)
        val t0 = c.tokens.value!!
        val t1 = c.tokenManager.refresh()
        assertNotEquals(t0.refreshToken, t1.refreshToken)
        assertNotEquals(t0.accessToken, t1.accessToken)

        rec.clear()
        val results = List(64) { async(Dispatchers.Default) { c.tokenManager.refresh() } }.awaitAll()
        assertEquals(1, rec.count("/oauth/token", grant = "refresh_token"), rec.entries.toString())
        assertEquals(1, results.map { it.refreshToken }.toSet().size)
        assertEquals(c.tokens.value!!.refreshToken, results.first().refreshToken)
        // The rotated token keeps working.
        assertEquals("alice", c.account.getMe().preferredUsername)
    }

    @Test
    fun `clients sharing one storage converge (cross-process lock and server grace window)`() = runBlocking {
        val storage = InMemorySecureStorage()
        val rec = Testbed.Recorder()
        val lock = Testbed.SharedLock()
        val a = Testbed.client(storage = storage, recorder = rec, lock = lock)
        a.signInWithPassword("alice", "Wonderland-Pass-1")
        val b = Testbed.client(storage = storage, recorder = rec, lock = lock)
        b.initialize()
        assertEquals(a.tokens.value, b.tokens.value)

        rec.clear()
        val (ra, rb) = listOf(a, b).map { c -> async(Dispatchers.Default) { c.tokenManager.refresh() } }.awaitAll()
        // With the lock the second client adopts the first one's result. (A client that never talked
        // to the server yet may need one use_dpop_nonce round trip, so count successful refreshes.)
        assertEquals(1, rec.count("/oauth/token", grant = "refresh_token", status = 200), rec.entries.toString())
        assertEquals(ra.refreshToken, rb.refreshToken)

        // Without a shared lock both send the same refresh token; the 60 s grace window returns one successor.
        val storage2 = InMemorySecureStorage()
        val x = Testbed.client(storage = storage2)
        x.signInWithPassword("alice", "Wonderland-Pass-1")
        val y = Testbed.client(storage = storage2)
        y.initialize()
        val (rx, ry) = listOf(x, y).map { c -> async(Dispatchers.Default) { c.tokenManager.refresh() } }.awaitAll()
        assertEquals(rx.refreshToken, ry.refreshToken)
        assertEquals("alice", y.account.getMe().preferredUsername)
    }

    @Test
    fun `profile update via API and server-side change arrive over SSE`() = runBlocking {
        val (user, pass) = Testbed.createUser()
        val c = signedInClient(user, pass)
        c.account.getMe()
        c.events.start()
        withTimeout(15_000) { c.events.state.first { it == EventStreamState.CONNECTED } }

        val name1 = "Name ${Testbed.randomName("")}"
        val viaSse = async { withTimeout(20_000) { c.events.events.first { it.type == UserEvent.USER_UPDATED && it.data?.nickname == name1 } } }
        yield()
        val updated = c.account.updateProfile(displayName = name1)
        assertEquals(name1, updated.nickname)
        assertEquals(name1, c.profile.value?.nickname)
        val ev = viaSse.await()
        assertEquals(updated.profileVersion, ev.data?.profileVersion)
        assertNotNull(c.events.lastReceivedEventId)

        // A change made elsewhere reaches the profile cache through SSE only.
        val name2 = "Server ${Testbed.randomName("")}"
        val changed = async { withTimeout(20_000) { c.profileChanges.first { it.nickname == name2 } } }
        yield()
        Testbed.setDisplayName(user, name2)
        val p = changed.await()
        assertTrue(p.profileVersion > updated.profileVersion)
        assertEquals(name2, c.profile.value?.nickname)

        // Optimistic concurrency with If-Match.
        val conflict = assertFailsWith<MoonSsoException> { c.account.updateProfile(displayName = "x", expectedVersion = updated.profileVersion) }
        assertEquals(412, conflict.httpStatus)
        c.events.stop()
        c.close()
    }

    @Test
    fun `native registration signs in a new user and reports validation errors`() = runBlocking {
        val info = Testbed.client().registrationInfo()
        assertTrue(info.registrationOpen)
        val username = Testbed.randomName()
        val c = Testbed.client()
        c.register(username, Testbed.randomPassword(), displayName = "新用户")
        assertIs<AuthState.SignedIn>(c.authState.value)
        val me = c.account.getMe()
        assertEquals(username, me.preferredUsername)
        assertEquals("新用户", me.nickname)

        val weak = assertFailsWith<MoonSsoException> { Testbed.client().register(Testbed.randomName(), "x") }
        assertEquals(422, weak.httpStatus)
        assertEquals("password", weak.field)
        val taken = assertFailsWith<MoonSsoException> { Testbed.client().register(username, Testbed.randomPassword()) }
        assertEquals(422, taken.httpStatus)
        assertEquals("username", taken.field)
    }

    @Test
    fun `avatar upload and removal`() = runBlocking {
        val (user, pass) = Testbed.createUser()
        val c = signedInClient(user, pass)
        val img = BufferedImage(64, 64, BufferedImage.TYPE_INT_RGB).apply {
            for (x in 0 until 64) for (y in 0 until 64) setRGB(x, y, (x * 4 shl 16) or (y * 4 shl 8) or 0x80)
        }
        val png = ByteArrayOutputStream().also { ImageIO.write(img, "png", it) }.toByteArray()
        val withAvatar = c.account.uploadAvatar(png, "image/png")
        assertNotNull(withAvatar.picture)
        assertEquals(withAvatar.picture, c.profile.value?.picture)
        val without = c.account.deleteAvatar()
        assertNull(without.picture)
        assertNull(c.profile.value?.picture)
    }

    @Test
    fun `password change keeps this device and the SSE event is handled`() = runBlocking {
        val (user, pass) = Testbed.createUser()
        val c = signedInClient(user, pass)
        val other = signedInClient(user, pass)
        c.events.start()
        withTimeout(15_000) { c.events.state.first { it == EventStreamState.CONNECTED } }
        val evt = async { withTimeout(20_000) { c.events.events.first { it.type == UserEvent.USER_PASSWORD_CHANGED } } }
        yield()
        val newPass = Testbed.randomPassword()
        c.account.changePassword(pass, newPass)
        evt.await()
        // This device refreshed successfully after the event and stays signed in.
        delay(500)
        assertIs<AuthState.SignedIn>(c.authState.value)
        assertEquals(user, c.account.getMe().preferredUsername)
        // The other device was signed out by the server.
        assertFailsWith<SessionExpiredException> { other.tokenManager.refresh() }
        assertIs<AuthState.SessionExpired>(other.authState.value)
        // The new password works.
        signedInClient(user, newPass).close()
        c.events.stop()
        c.close()
    }

    @Test
    fun `401 from the API triggers one refresh and a replay`() = runBlocking {
        val rec = Testbed.Recorder()
        val c = signedInClient("alice", "Wonderland-Pass-1", recorder = rec)
        val before = c.tokens.value!!.accessToken
        revoke(before)
        rec.clear()
        assertEquals("alice", c.account.getMe().preferredUsername)
        assertEquals(1, rec.entries.count { it.path == "/api/v1/me" && it.status == 401 }, rec.entries.toString())
        assertEquals(1, rec.count("/oauth/token", grant = "refresh_token"))
        assertNotEquals(before, c.tokens.value!!.accessToken)
    }

    @Test
    fun `revoked refresh token ends the session with SessionExpired`() = runBlocking {
        val c = signedInClient("alice", "Wonderland-Pass-1")
        revoke(c.tokens.value!!.refreshToken!!)
        val expired = async { withTimeout(10_000) { c.sessionExpired.first() } }
        yield()
        assertFailsWith<SessionExpiredException> { c.tokenManager.refresh() }
        assertNotNull(expired.await())
        assertIs<AuthState.SessionExpired>(c.authState.value)
        assertNull(c.tokens.value)
    }

    @Test
    fun `dynamic client registration creates a usable client`() = runBlocking {
        val dcr = DynamicClientRegistration(Testbed.issuer)
        val reg = try {
            dcr.registerClient(
                Testbed.initialAccessToken(),
                ClientMetadata(
                    clientName = "Kotlin SDK test ${Testbed.randomName("")}",
                    redirectUris = listOf("http://127.0.0.1/callback"),
                    tokenEndpointAuthMethod = "none",
                    applicationType = "native",
                    grantTypes = listOf("authorization_code", "refresh_token"),
                    scope = "openid profile offline_access",
                ),
            )
        } catch (e: MoonSsoException) {
            // The testbed's initial access tokens all belong to alice, who may own at most
            // max_clients_per_developer (10) clients; suites that do not delete theirs exhaust it.
            assumeTrue(!(e.httpStatus == 403 && e.error == "access_denied"), "testbed DCR quota exhausted: ${e.errorDescription}")
            throw e
        }
        try {
            assertTrue(reg.clientId.isNotEmpty())
            assertNull(reg.clientSecret)
            assertNotNull(reg.registrationAccessToken)
            assertEquals("active", reg.status)
            assertTrue(reg.registrationAccessToken!! !in reg.toString())

            Testbed.trustClient(reg.clientId)
            val c = Testbed.client(clientId = reg.clientId, scopes = listOf("openid", "profile", "offline_access"))
            c.signInWithPassword("alice", "Wonderland-Pass-1")
            assertEquals("alice", c.account.getMe().preferredUsername)
            c.close()
        } finally {
            // RFC 7592: remove the client again so the shared quota is not used up.
            dcr.deleteClient(reg)
        }
        val e = assertFailsWith<MoonSsoException> { dcr.deleteClient(reg) }
        assertEquals(401, e.httpStatus)
    }

    private fun revoke(token: String) {
        val body = FormBody.Builder().add("token", token).add("client_id", "test-native").build()
        OkHttpClient().newCall(Request.Builder().url("${Testbed.issuer}/oauth/revoke").post(body).build()).execute().use {
            check(it.isSuccessful) { "revoke failed: HTTP ${it.code}" }
        }
    }
}
