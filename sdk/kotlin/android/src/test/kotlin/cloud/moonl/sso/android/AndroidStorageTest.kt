package cloud.moonl.sso.android

import cloud.moonl.sso.MoonSsoLogger
import cloud.moonl.sso.PendingAuthorization
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull

/** JVM unit tests of the Android storage logic (the Keystore key is replaced by a software AES key). */
class AndroidStorageTest {
    private class MapStore : KeyValueStore {
        val map = HashMap<String, String>()
        override fun get(key: String): String? = map[key]
        override fun put(key: String, value: String) {
            map[key] = value
        }
        override fun remove(key: String) {
            map.remove(key)
        }
    }

    private val key: SecretKey = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
    private val encryptor = AesGcmEncryptor { key }

    @Test
    fun `AES-GCM round trip with random IVs and authenticated data`() {
        val plain = "refresh-token-value".toByteArray()
        val a = encryptor.encrypt(plain, "aad".toByteArray())
        val b = encryptor.encrypt(plain, "aad".toByteArray())
        assertNotEquals(a.toList(), b.toList())
        assertContentEquals(plain, encryptor.decrypt(a, "aad".toByteArray()))
        assertFailsWith<Exception> { encryptor.decrypt(a, "other".toByteArray()) }
        a[a.size - 1] = (a[a.size - 1].toInt() xor 1).toByte()
        assertFailsWith<Exception> { encryptor.decrypt(a, "aad".toByteArray()) }
    }

    @Test
    fun `session storage round trip stores only ciphertext`() {
        val kv = MapStore()
        val storage = EncryptedValueStorage(kv, "session", encryptor, MoonSsoLogger.None)
        assertNull(storage.read())
        val json = """{"refresh_token":"rt-secret","access_token":"at","expires_at":123}"""
        storage.write(json)
        assertFalse(kv.map.values.single().contains("rt-secret"))
        assertEquals(json, EncryptedValueStorage(kv, "session", encryptor, MoonSsoLogger.None).read())
        storage.clear()
        assertNull(storage.read())
    }

    @Test
    fun `undecryptable data (lost Keystore key) reads as signed out and is removed`() {
        val kv = MapStore()
        EncryptedValueStorage(kv, "session", encryptor, MoonSsoLogger.None).write("secret")
        val otherKey = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
        val other = EncryptedValueStorage(kv, "session", AesGcmEncryptor { otherKey }, MoonSsoLogger.None)
        assertNull(other.read())
        assertEquals(emptyMap(), kv.map)
    }

    private fun pending(createdAt: Long) = PendingAuthorization(
        authorizationUrl = "https://sso.example/oauth/authorize?client_id=x",
        redirectUri = "com.example.test:/oauth2redirect",
        state = "state-1",
        nonce = "nonce-1",
        codeVerifier = "v".repeat(43),
        scope = "openid",
        createdAt = createdAt,
    )

    @Test
    fun `pending login survives process death and accepts only its own redirect`() {
        val kv = MapStore()
        val store = PendingAuthStore(EncryptedValueStorage(kv, "pending_authorization", encryptor, MoonSsoLogger.None))
        store.save(PendingLoginRecord(pending(1_000), returnActivity = "com.example.MainActivity"))
        assertFalse(kv.map.values.single().contains("v".repeat(43)), "verifier must be encrypted")

        // "New process": a fresh store over the same preferences.
        val again = PendingAuthStore(EncryptedValueStorage(kv, "pending_authorization", encryptor, MoonSsoLogger.None))
        assertNull(again.acceptCallback("com.other:/oauth2redirect?code=c&state=state-1", 1_010))
        val accepted = again.acceptCallback("com.example.test:/oauth2redirect?code=c&state=state-1&iss=x", 1_010)
        assertEquals("com.example.MainActivity", accepted?.returnActivity)
        assertEquals("com.example.test:/oauth2redirect?code=c&state=state-1&iss=x", again.load()?.callback)
        assertEquals("state-1", again.load()?.pending?.state)
    }

    @Test
    fun `stale pending login is discarded`() {
        val kv = MapStore()
        val store = PendingAuthStore(EncryptedValueStorage(kv, "pending_authorization", encryptor, MoonSsoLogger.None))
        store.save(PendingLoginRecord(pending(1_000)))
        assertNull(store.acceptCallback("com.example.test:/oauth2redirect?code=c", 1_000 + PendingAuthStore.MAX_AGE_SECONDS + 1))
        assertNull(store.load())
    }

    @Test
    fun `default redirect uri uses the reverse-domain scheme`() {
        assertEquals("com.example.test:/oauth2redirect", MoonSsoAndroid.defaultRedirectUri("com.example.test"))
    }
}
