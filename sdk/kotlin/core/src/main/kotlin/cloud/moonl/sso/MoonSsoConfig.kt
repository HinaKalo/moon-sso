package cloud.moonl.sso

import java.net.URI

/**
 * Static configuration of one Moon SSO client application.
 *
 * Only the [issuer] is configured; every endpoint is discovered through
 * `/.well-known/openid-configuration`.
 */
public class MoonSsoConfig(
    /** Issuer URL, e.g. `https://sso.moonl.cloud` (no trailing slash). */
    issuer: String,
    /** OAuth client_id registered at Moon SSO. */
    public val clientId: String,
    /** Scopes requested by default for logins. */
    public val scopes: List<String> = DEFAULT_SCOPES,
    /**
     * Use DPoP (RFC 9449) for the token, challenge and native registration endpoints.
     * Public clients enable it by default; it is mandatory for clients with `require_dpop`.
     */
    public val useDpop: Boolean = true,
    /** Fraction of the access token lifetime after which it is refreshed proactively. */
    public val refreshAtLifetimeFraction: Double = 0.75,
    /** Refresh tokens in the background when they reach [refreshAtLifetimeFraction] of their lifetime. */
    public val autoRefresh: Boolean = true,
    /** Additional hosts (besides the issuer host) that may receive the access token from the OkHttp interceptor. */
    public val trustedApiHosts: Set<String> = emptySet(),
    /** User-Agent sent on every request; Moon SSO shows `moon-sso-sdk` clients as “应用 SDK”. */
    public val userAgent: String = DEFAULT_USER_AGENT,
    /** Logger for diagnostics. Messages never contain tokens, codes or passwords. */
    public val logger: MoonSsoLogger = MoonSsoLogger.Default,
) {
    /** Normalized issuer URL without trailing slash. */
    public val issuer: String = issuer.trimEnd('/')

    init {
        require(clientId.isNotBlank()) { "clientId must not be blank" }
        require(refreshAtLifetimeFraction > 0.0 && refreshAtLifetimeFraction < 1.0) {
            "refreshAtLifetimeFraction must be within (0, 1)"
        }
        val uri = try {
            URI(this.issuer)
        } catch (e: Exception) {
            throw IllegalArgumentException("issuer is not a valid URL", e)
        }
        require(uri.scheme == "https" || (uri.scheme == "http" && isLoopbackHost(uri.host))) {
            "issuer must use https (http is only allowed for loopback test servers)"
        }
        require(uri.rawQuery == null && uri.rawFragment == null) { "issuer must not contain a query or fragment" }
    }

    /** Space separated default scope string. */
    public val scopeString: String get() = scopes.joinToString(" ")

    public companion object {
        /** SDK version reported in the User-Agent. */
        public const val SDK_VERSION: String = "1.0.0"

        /** `moon-sso-sdk-kotlin/<version>`. */
        public const val DEFAULT_USER_AGENT: String = "moon-sso-sdk-kotlin/$SDK_VERSION"

        /** Production issuer. */
        public const val PRODUCTION_ISSUER: String = "https://sso.moonl.cloud"

        /** `openid profile offline_access`. */
        public val DEFAULT_SCOPES: List<String> = listOf("openid", "profile", "offline_access")

        internal fun isLoopbackHost(host: String?): Boolean =
            host == "127.0.0.1" || host == "localhost" || host == "::1" || host == "[::1]"
    }
}

/** Minimal logging hook. Implementations must not assume messages are free of user names, but they never contain secrets. */
public fun interface MoonSsoLogger {
    public fun log(level: Level, message: String, error: Throwable?)

    public enum class Level { DEBUG, INFO, WARN, ERROR }

    public companion object {
        /** Logs through `java.util.logging` under the name `cloud.moonl.sso`. */
        public val Default: MoonSsoLogger = MoonSsoLogger { level, message, error ->
            val jul = java.util.logging.Logger.getLogger("cloud.moonl.sso")
            val julLevel = when (level) {
                Level.DEBUG -> java.util.logging.Level.FINE
                Level.INFO -> java.util.logging.Level.INFO
                Level.WARN -> java.util.logging.Level.WARNING
                Level.ERROR -> java.util.logging.Level.SEVERE
            }
            if (jul.isLoggable(julLevel)) jul.log(julLevel, message, error)
        }

        /** Discards everything. */
        public val None: MoonSsoLogger = MoonSsoLogger { _, _, _ -> }
    }
}

internal fun MoonSsoLogger.debug(message: String) = log(MoonSsoLogger.Level.DEBUG, message, null)
internal fun MoonSsoLogger.info(message: String) = log(MoonSsoLogger.Level.INFO, message, null)
internal fun MoonSsoLogger.warn(message: String, error: Throwable? = null) = log(MoonSsoLogger.Level.WARN, message, error)
