package cloud.moonl.sso

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject

/**
 * Tokens of the current session. `issuedAt`/`expiresAt` are epoch seconds computed locally
 * (`expires_at = now + expires_in`). [toString] never prints token values.
 */
@Serializable
public data class TokenSet(
    @SerialName("access_token") val accessToken: String,
    @SerialName("token_type") val tokenType: String = "Bearer",
    @SerialName("refresh_token") val refreshToken: String? = null,
    @SerialName("id_token") val idToken: String? = null,
    @SerialName("scope") val scope: String? = null,
    @SerialName("issued_at") val issuedAt: Long,
    @SerialName("expires_at") val expiresAt: Long,
) {
    /** Granted scopes. */
    val scopes: List<String> get() = scope?.split(' ')?.filter { it.isNotEmpty() } ?: emptyList()

    /** Epoch milliseconds at which the token should be refreshed proactively. */
    public fun refreshDueAtMillis(fraction: Double): Long {
        val lifetimeMs = (expiresAt - issuedAt).coerceAtLeast(0) * 1000
        return issuedAt * 1000 + (lifetimeMs * fraction).toLong()
    }

    override fun toString(): String =
        "TokenSet(tokenType=$tokenType, scope=$scope, issuedAt=$issuedAt, expiresAt=$expiresAt, " +
            "refreshToken=${if (refreshToken != null) "<redacted>" else "null"}, idToken=${if (idToken != null) "<redacted>" else "null"})"
}

/** The user's profile as seen by this client (`GET /api/v1/me`). */
@Serializable
public data class Profile(
    val sub: String,
    @SerialName("preferred_username") val preferredUsername: String? = null,
    val name: String? = null,
    val nickname: String? = null,
    val picture: String? = null,
    @SerialName("updated_at") val updatedAt: Long? = null,
    @SerialName("profile_version") val profileVersion: Long = 0,
    @SerialName("totp_enabled") val totpEnabled: Boolean? = null,
)

/** Payload of a user event (SSE, webhooks, change feed). */
@Serializable
public data class UserEventData(
    val sub: String? = null,
    val status: String? = null,
    @SerialName("preferred_username") val preferredUsername: String? = null,
    val name: String? = null,
    val nickname: String? = null,
    val picture: String? = null,
    @SerialName("profile_version") val profileVersion: Long? = null,
    @SerialName("updated_at") val updatedAt: Long? = null,
    val changed: List<String> = emptyList(),
)

/** A user event delivered over SSE. [type] is e.g. `user.updated`, `user.password_changed`, `resync`, `token_expired`. */
@Serializable
public data class UserEvent(
    val id: String? = null,
    val seq: Long? = null,
    val type: String = "",
    @SerialName("occurred_at") val occurredAt: String? = null,
    val data: UserEventData? = null,
) {
    public companion object {
        public const val USER_UPDATED: String = "user.updated"
        public const val USER_PASSWORD_CHANGED: String = "user.password_changed"
        public const val USER_DISABLED: String = "user.disabled"
        public const val USER_ENABLED: String = "user.enabled"
        public const val USER_DELETED: String = "user.deleted"
        public const val CONSENT_REVOKED: String = "consent.revoked"
        public const val RESYNC: String = "resync"
        public const val TOKEN_EXPIRED: String = "token_expired"
    }
}

/** Login state of a [MoonSsoClient]. */
public sealed interface AuthState {
    /** Storage has not been read yet (`MoonSsoClient.initialize()` not completed). */
    public data object Loading : AuthState

    public data object SignedOut : AuthState

    public data class SignedIn(val subject: String?, val scopes: List<String>, val expiresAt: Long) : AuthState

    /** The refresh token was rejected (`invalid_grant`); local tokens were removed. */
    public data class SessionExpired(val reason: String?) : AuthState
}

/** Emitted on `MoonSsoClient.sessionExpired` when the session ends because a refresh returned `invalid_grant`. */
public data class SessionExpiredEvent(val reason: String?)

/** Pending second-factor step of a first-party login. */
public class OtpChallenge internal constructor(
    /** Opaque `auth_session` returned by the server. */
    public val authSession: String,
    /** Required factor, currently always `otp`. */
    public val required: String,
    internal val pkce: Pkce,
    internal val scope: String,
) {
    override fun toString(): String = "OtpChallenge(required=$required)"
}

/**
 * State of a browser-based authorization request. Persist it (it is serializable) to survive
 * process death; it contains the PKCE verifier, so keep it in private app storage only.
 */
@Serializable
public data class PendingAuthorization(
    @SerialName("authorization_url") val authorizationUrl: String,
    @SerialName("redirect_uri") val redirectUri: String,
    val state: String,
    val nonce: String,
    @SerialName("code_verifier") val codeVerifier: String,
    val scope: String,
    @SerialName("created_at") val createdAt: Long,
) {
    override fun toString(): String = "PendingAuthorization(redirectUri=$redirectUri, scope=$scope, createdAt=$createdAt)"
}

/** `GET /api/v1/registration`. */
@Serializable
public data class RegistrationInfo(
    @SerialName("registration_open") val registrationOpen: Boolean = false,
    @SerialName("password_min_length") val passwordMinLength: Int? = null,
    @SerialName("username_pattern") val usernamePattern: String? = null,
    @SerialName("client_registration") val clientRegistration: String? = null,
)

/** Verified ID token claims. */
public class IdTokenClaims internal constructor(
    public val subject: String,
    public val issuedAt: Long,
    public val expiresAt: Long,
    public val nonce: String?,
    public val sessionId: String?,
    /** All claims as JSON. */
    public val claims: JsonObject,
)

/** Verified access token claims (resource server use). */
public class AccessTokenClaims internal constructor(
    public val subject: String,
    public val clientId: String?,
    public val scopes: List<String>,
    public val audience: List<String>,
    public val expiresAt: Long,
    public val claims: JsonObject,
)
