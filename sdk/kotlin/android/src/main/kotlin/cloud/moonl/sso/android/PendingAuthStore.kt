package cloud.moonl.sso.android

import cloud.moonl.sso.PendingAuthorization
import cloud.moonl.sso.storage.SecureStorage
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/** Persisted browser login in progress (survives process death while the Custom Tab is open). */
@Serializable
internal data class PendingLoginRecord(
    val pending: PendingAuthorization,
    /** Activity to bring back to the front after the redirect (the one that started the login). */
    @SerialName("return_activity") val returnActivity: String? = null,
    /** Redirect URI received by [MoonSsoRedirectActivity], waiting to be exchanged. */
    val callback: String? = null,
)

/** Encrypted persistence of [PendingLoginRecord]. */
internal class PendingAuthStore(private val storage: SecureStorage) {
    private val json = Json { ignoreUnknownKeys = true; explicitNulls = false }

    @Synchronized
    fun load(): PendingLoginRecord? = try {
        storage.read()?.let { json.decodeFromString(PendingLoginRecord.serializer(), it) }
    } catch (_: Exception) {
        storage.clear()
        null
    }

    @Synchronized
    fun save(record: PendingLoginRecord) = storage.write(json.encodeToString(PendingLoginRecord.serializer(), record))

    @Synchronized
    fun clear() = storage.clear()

    /**
     * Records the redirect when it belongs to the pending login. Returns the activity to resume, or
     * null when there is no matching login (stale or foreign redirect).
     */
    @Synchronized
    fun acceptCallback(uri: String, nowSeconds: Long): PendingLoginRecord? {
        val record = load() ?: return null
        val base = uri.substringBefore('#').substringBefore('?')
        if (base != record.pending.redirectUri) return null
        if (nowSeconds - record.pending.createdAt > MAX_AGE_SECONDS) {
            clear()
            return null
        }
        val updated = record.copy(callback = uri)
        save(updated)
        return updated
    }

    companion object {
        /** A login left open longer than this is discarded. */
        const val MAX_AGE_SECONDS = 30 * 60L
    }
}
