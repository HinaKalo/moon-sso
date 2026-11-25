package cloud.moonl.sso

import java.io.IOException

/**
 * Error raised by every SDK operation.
 *
 * [error] is an OAuth error code returned by the server (`invalid_grant`, `access_denied`, ...),
 * or one of the SDK codes [NETWORK], [INVALID_RESPONSE], [LOGIN_REQUIRED], [TIMEOUT], [STATE_MISMATCH].
 */
public open class MoonSsoException(
    public val error: String,
    public val errorDescription: String? = null,
    /** HTTP status of the failed response, when there was one. */
    public val httpStatus: Int? = null,
    /** Offending form field for 422 validation errors. */
    public val field: String? = null,
    cause: Throwable? = null,
) : Exception(buildMessage(error, errorDescription, httpStatus, field), cause) {

    /** True for transient failures (network, 5xx, 429) that never end the session. */
    public val isTransient: Boolean
        get() = error == NETWORK || (httpStatus != null && (httpStatus >= 500 || httpStatus == 429))

    public companion object {
        public const val NETWORK: String = "network"
        public const val INVALID_RESPONSE: String = "invalid_response"
        public const val LOGIN_REQUIRED: String = "login_required"
        public const val TIMEOUT: String = "timeout"
        public const val STATE_MISMATCH: String = "state_mismatch"
        public const val INVALID_GRANT: String = "invalid_grant"

        private fun buildMessage(error: String, description: String?, status: Int?, field: String?): String = buildString {
            append(error)
            if (!description.isNullOrBlank()) append(": ").append(description)
            if (field != null) append(" [field=").append(field).append(']')
            if (status != null) append(" (HTTP ").append(status).append(')')
        }
    }
}

/**
 * The first-party login needs a second factor. Ask the user for the code and call
 * `MoonSsoClient.submitOtp(challenge, code)`; the challenge keeps the PKCE verifier of the first step.
 */
public class OtpRequiredException(
    public val challenge: OtpChallenge,
    errorDescription: String?,
) : MoonSsoException("insufficient_authorization", errorDescription, 400)

/** An administrator reset the password; the user must set a new one in the browser at [changeUrl]. */
public class PasswordChangeRequiredException(
    public val changeUrl: String?,
    errorDescription: String?,
) : MoonSsoException("password_change_required", errorDescription, 400)

/** The refresh token was rejected with `invalid_grant`: the session is over and the user must sign in again. */
public class SessionExpiredException(
    errorDescription: String?,
    cause: Throwable? = null,
) : MoonSsoException(INVALID_GRANT, errorDescription, 400, null, cause)

/** Thrown from OkHttp interceptors/authenticators so that OkHttp treats SDK failures as I/O failures. */
public class MoonSsoIOException(public val error: MoonSsoException) : IOException(error.message, error)
