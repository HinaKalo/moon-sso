package cloud.moonl.sso

import cloud.moonl.sso.dpop.StoredDpopKeyProvider
import cloud.moonl.sso.internal.SdkJson
import cloud.moonl.sso.storage.InMemorySecureStorage
import cloud.moonl.sso.storage.NoCrossProcessLock
import cloud.moonl.sso.storage.PersistedState
import cloud.moonl.sso.storage.SessionStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class SessionStoreTest {
    private val issuer = "https://sso.example"
    private fun store(storage: InMemorySecureStorage) =
        SessionStore(storage, NoCrossProcessLock, issuer, "app", Dispatchers.Unconfined, MoonSsoLogger.None)

    private val tokens = TokenSet("at-1", "Bearer", "rt-1", "idt-1", "openid profile", 1000, 1600)

    @Test
    fun `round-trips tokens and profile through the storage`() = runTest {
        val storage = InMemorySecureStorage()
        val s = store(storage)
        s.transaction { tx -> tx.write(tx.current.withTokens(tokens, "sub-1").copy(profile = Profile("sub-1", "alice", profileVersion = 3))) }

        val again = store(storage).reload()
        assertEquals(tokens, again.tokens())
        assertEquals("sub-1", again.sub)
        assertEquals(3, again.profile?.profileVersion)
        val json = storage.read()!!
        // Field names required by the spec.
        for (k in listOf("refresh_token", "access_token", "expires_at", "id_token", "profile")) assertTrue("\"$k\"" in json, k)
    }

    @Test
    fun `sign out keeps the installation's DPoP key`() = runTest {
        val storage = InMemorySecureStorage()
        val s = store(storage)
        val key = StoredDpopKeyProvider(s).key()
        s.transaction { tx -> tx.write(tx.current.withTokens(tokens, "sub-1")) }
        s.transaction { tx -> tx.write(tx.current.signedOut()) }
        val after = store(storage).reload()
        assertNull(after.tokens())
        assertNotNull(after.dpopKey)
        assertEquals(key.thumbprint, StoredDpopKeyProvider(store(storage).also { it.reload() }).key().thumbprint)
    }

    @Test
    fun `concurrent key generation converges on one key`() = runTest {
        val storage = InMemorySecureStorage()
        val stores = List(8) { store(storage) }
        val prints = stores.map { st -> async { StoredDpopKeyProvider(st).key().thumbprint } }.awaitAll()
        assertEquals(1, prints.toSet().size)
    }

    @Test
    fun `corrupt or foreign storage starts signed out`() = runTest {
        assertNull(store(InMemorySecureStorage("{not json")).reload().tokens())
        val foreign = SdkJson.encodeToString(
            PersistedState.serializer(),
            PersistedState(issuer = issuer, clientId = "other").withTokens(tokens, "x").copy(dpopKey = "k"),
        )
        val loaded = store(InMemorySecureStorage(foreign)).reload()
        assertNull(loaded.tokens())
        assertEquals("k", loaded.dpopKey)
    }

    @Test
    fun `toString never contains secrets`() {
        val text = tokens.toString() + PersistedState().withTokens(tokens, "s").toString()
        assertFalse("at-1" in text || "rt-1" in text || "idt-1" in text, text)
    }
}
