package cloud.moonl.sso.storage

import cloud.moonl.sso.MoonSsoLogger
import cloud.moonl.sso.Profile
import cloud.moonl.sso.TokenSet
import cloud.moonl.sso.internal.SdkJson
import cloud.moonl.sso.warn
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/** JSON document kept in [SecureStorage]. */
@Serializable
internal data class PersistedState(
    val version: Int = 1,
    val issuer: String? = null,
    @SerialName("client_id") val clientId: String? = null,
    @SerialName("access_token") val accessToken: String? = null,
    @SerialName("token_type") val tokenType: String? = null,
    @SerialName("refresh_token") val refreshToken: String? = null,
    @SerialName("id_token") val idToken: String? = null,
    val scope: String? = null,
    @SerialName("issued_at") val issuedAt: Long? = null,
    @SerialName("expires_at") val expiresAt: Long? = null,
    val sub: String? = null,
    val profile: Profile? = null,
    /** Private P-256 JWK of the DPoP key (JVM/desktop only; Android keeps it in the Keystore). */
    @SerialName("dpop_key") val dpopKey: String? = null,
) {
    fun tokens(): TokenSet? {
        val at = accessToken ?: return null
        return TokenSet(
            accessToken = at,
            tokenType = tokenType ?: "Bearer",
            refreshToken = refreshToken,
            idToken = idToken,
            scope = scope,
            issuedAt = issuedAt ?: 0,
            expiresAt = expiresAt ?: 0,
        )
    }

    fun withTokens(t: TokenSet, subject: String?): PersistedState = copy(
        accessToken = t.accessToken,
        tokenType = t.tokenType,
        refreshToken = t.refreshToken,
        idToken = t.idToken,
        scope = t.scope,
        issuedAt = t.issuedAt,
        expiresAt = t.expiresAt,
        sub = subject,
        profile = if (subject != null && profile?.sub == subject) profile else null,
    )

    /** Removes everything that belongs to the session; the long-lived DPoP key stays. */
    fun signedOut(): PersistedState = PersistedState(issuer = issuer, clientId = clientId, dpopKey = dpopKey)

    override fun toString(): String = "PersistedState(sub=$sub, hasTokens=${accessToken != null})"
}

/**
 * In-memory view of the persisted session with transactional updates. Every write happens inside
 * [transaction]: in-process mutex, then the [CrossProcessLock], then a fresh read of the storage.
 */
internal class SessionStore(
    private val storage: SecureStorage,
    private val lock: CrossProcessLock,
    private val issuer: String,
    private val clientId: String,
    private val io: CoroutineDispatcher,
    private val logger: MoonSsoLogger,
) {
    private val mutex = Mutex()

    @Volatile
    var state: PersistedState = PersistedState(issuer = issuer, clientId = clientId)
        private set

    /** Listener invoked after the in-memory state changed (from any transaction or reload). */
    @Volatile
    var onChange: ((PersistedState) -> Unit)? = null

    interface Tx {
        /** State read from storage after acquiring the locks. */
        val current: PersistedState

        /** Writes [next] durably and makes it the current state. */
        suspend fun write(next: PersistedState)
    }

    /** Re-reads the storage without locking (used at start-up). */
    suspend fun reload(): PersistedState = mutex.withLock {
        lock.withLock { readFresh() }
    }

    suspend fun <T> transaction(block: suspend (Tx) -> T): T = mutex.withLock {
        lock.withLock {
            val fresh = readFresh()
            val tx = object : Tx {
                override var current: PersistedState = fresh

                override suspend fun write(next: PersistedState) {
                    val encoded = SdkJson.encodeToString(PersistedState.serializer(), next)
                    withContext(io) { storage.write(encoded) }
                    current = next
                    publish(next)
                }
            }
            block(tx)
        }
    }

    private suspend fun readFresh(): PersistedState {
        val raw = try {
            withContext(io) { storage.read() }
        } catch (e: Exception) {
            logger.warn("secure storage could not be read; continuing signed out", e)
            null
        }
        val parsed = when {
            raw.isNullOrBlank() -> PersistedState(issuer = issuer, clientId = clientId)
            else -> try {
                val s = SdkJson.decodeFromString(PersistedState.serializer(), raw)
                if (s.issuer != issuer || s.clientId != clientId) {
                    logger.warn("stored session belongs to another issuer or client; ignoring its tokens")
                    PersistedState(issuer = issuer, clientId = clientId, dpopKey = s.dpopKey)
                } else {
                    s
                }
            } catch (e: Exception) {
                // The parser's message may quote the stored JSON (tokens): log the type only.
                logger.warn("stored session is corrupt (${e.javaClass.simpleName}); continuing signed out")
                PersistedState(issuer = issuer, clientId = clientId)
            }
        }
        publish(parsed)
        return parsed
    }

    private fun publish(s: PersistedState) {
        val changed = s != state
        state = s
        if (changed) onChange?.invoke(s)
    }
}
