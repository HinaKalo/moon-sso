package cloud.moonl.sso

import cloud.moonl.sso.internal.SdkJson
import cloud.moonl.sso.internal.decode
import cloud.moonl.sso.internal.requireSuccess
import cloud.moonl.sso.internal.send
import cloud.moonl.sso.storage.SessionStore
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

/** Cached profile with change notifications (persisted together with the session). */
internal class ProfileState(private val store: SessionStore) {
    private val _profile = MutableStateFlow<Profile?>(null)
    private val _changes = MutableSharedFlow<Profile>(replay = 0, extraBufferCapacity = 64)

    val profile: StateFlow<Profile?> = _profile.asStateFlow()
    val changes: SharedFlow<Profile> = _changes.asSharedFlow()

    fun onStoreChanged(p: Profile?) {
        _profile.value = p
    }

    /**
     * Stores [next] unless an equal or newer version of the same user is already cached.
     * Returns true when the cached profile changed.
     */
    suspend fun update(next: Profile, force: Boolean = false): Boolean {
        val changed = store.transaction { tx ->
            val cur = tx.current.profile
            val sub = tx.current.sub
            if (tx.current.accessToken == null) return@transaction false
            if (sub != null && sub != next.sub) return@transaction false
            if (!force && cur != null && cur.sub == next.sub && cur.profileVersion > next.profileVersion) return@transaction false
            val merged = if (next.totpEnabled == null && cur?.sub == next.sub) next.copy(totpEnabled = cur.totpEnabled) else next
            if (merged == cur) return@transaction false
            tx.write(tx.current.copy(profile = merged))
            true
        }
        if (changed) {
            _profile.value = store.state.profile
            store.state.profile?.let { _changes.tryEmit(it) }
        }
        return changed
    }
}

/**
 * Account API (`/api/v1/me`). Requests go through the authorized OkHttp client (token attached,
 * proactive refresh, one refresh-and-replay on 401). Successful calls update the cached profile and
 * emit on `MoonSsoClient.profileChanges`.
 */
public class AccountApi internal constructor(
    private val issuer: String,
    private val http: OkHttpClient,
    private val profiles: ProfileState,
) {
    private val base = "$issuer/api/v1"

    /** `GET /api/v1/me` (scope `profile`). */
    public suspend fun getMe(): Profile {
        val res = http.send(Request.Builder().url("$base/me").header("Accept", "application/json").get().build()).requireSuccess()
        val p = res.decode<Profile>()
        profiles.update(p, force = true)
        return p
    }

    /**
     * `PATCH /api/v1/me` (scope `profile:write`). [expectedVersion] sends `If-Match: "pv-<n>"`;
     * a concurrent change then fails with `version_conflict` (HTTP 412).
     */
    public suspend fun updateProfile(username: String? = null, displayName: String? = null, expectedVersion: Long? = null): Profile {
        require(username != null || displayName != null) { "nothing to update" }
        val body = buildJsonObject {
            username?.let { put("username", JsonPrimitive(it)) }
            displayName?.let { put("display_name", JsonPrimitive(it)) }
        }
        val req = Request.Builder()
            .url("$base/me")
            .header("Accept", "application/json")
            .apply { expectedVersion?.let { header("If-Match", "\"pv-$it\"") } }
            .patch(SdkJson.encodeToString(kotlinx.serialization.json.JsonObject.serializer(), body).toRequestBody(JSON))
            .build()
        val p = http.send(req).requireSuccess().decode<Profile>()
        profiles.update(p)
        return p
    }

    /** `PUT /api/v1/me/avatar` with the raw image bytes (≤ 5 MB, PNG/JPEG/WebP/GIF). */
    public suspend fun uploadAvatar(image: ByteArray, contentType: String): Profile {
        require(contentType.startsWith("image/")) { "contentType must be an image type" }
        if (image.size > MAX_AVATAR_BYTES) {
            throw MoonSsoException("avatar_too_large", "avatar must not exceed 5 MB", 413)
        }
        val req = Request.Builder()
            .url("$base/me/avatar")
            .header("Accept", "application/json")
            .put(image.toRequestBody(contentType.toMediaType()))
            .build()
        val p = http.send(req).requireSuccess().decode<Profile>()
        profiles.update(p)
        return p
    }

    /** `DELETE /api/v1/me/avatar`. */
    public suspend fun deleteAvatar(): Profile {
        val req = Request.Builder().url("$base/me/avatar").header("Accept", "application/json").delete().build()
        val p = http.send(req).requireSuccess().decode<Profile>()
        profiles.update(p)
        return p
    }

    /**
     * `POST /api/v1/me/password` (scope `password:write`). Other devices are signed out; this
     * device keeps its session unless [keepThisDevice] is false.
     */
    public suspend fun changePassword(currentPassword: String, newPassword: String, keepThisDevice: Boolean = true) {
        val body = buildJsonObject {
            put("current_password", currentPassword)
            put("new_password", newPassword)
            put("keep_this_device", keepThisDevice)
        }
        val req = Request.Builder()
            .url("$base/me/password")
            .header("Accept", "application/json")
            .post(SdkJson.encodeToString(kotlinx.serialization.json.JsonObject.serializer(), body).toRequestBody(JSON))
            .build()
        http.send(req).requireSuccess()
    }

    private companion object {
        val JSON = "application/json; charset=utf-8".toMediaType()
        const val MAX_AVATAR_BYTES = 5 * 1024 * 1024
    }
}
