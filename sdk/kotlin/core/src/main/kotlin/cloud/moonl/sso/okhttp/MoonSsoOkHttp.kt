package cloud.moonl.sso.okhttp

import cloud.moonl.sso.MoonSsoException
import cloud.moonl.sso.MoonSsoIOException
import cloud.moonl.sso.TokenManager
import kotlinx.coroutines.runBlocking
import okhttp3.Authenticator
import okhttp3.HttpUrl
import okhttp3.Interceptor
import okhttp3.Request
import okhttp3.Response
import okhttp3.Route

/** Decides which requests may carry the access token. */
public fun interface TokenHostPolicy {
    public fun allows(url: HttpUrl): Boolean
}

private const val BEARER = "Bearer "

/**
 * Attaches `Authorization: Bearer <access token>` to requests for trusted hosts, refreshing the token
 * first when 75% of its lifetime is used. Requests that already carry an Authorization header are
 * left untouched. Shares the single-flight refresh of [TokenManager] with [MoonSsoAuthenticator].
 */
public class MoonSsoAuthInterceptor(
    private val tokens: TokenManager,
    private val hostPolicy: TokenHostPolicy,
) : Interceptor {
    override fun intercept(chain: Interceptor.Chain): Response {
        val request = chain.request()
        if (request.header("Authorization") != null || !hostPolicy.allows(request.url)) {
            return chain.proceed(request)
        }
        val token = try {
            runBlocking { tokens.accessToken() }
        } catch (e: MoonSsoException) {
            throw MoonSsoIOException(e)
        }
        return chain.proceed(request.newBuilder().header("Authorization", BEARER + token).build())
    }
}

/**
 * On `401 Unauthorized` forces one refresh (shared with concurrent callers) and replays the request
 * once with the new token. A second 401 is returned to the caller; the session is only discarded
 * when the refresh itself fails with `invalid_grant`.
 */
public class MoonSsoAuthenticator(
    private val tokens: TokenManager,
    private val hostPolicy: TokenHostPolicy,
) : Authenticator {
    override fun authenticate(route: Route?, response: Response): Request? {
        val request = response.request
        if (!hostPolicy.allows(request.url)) return null
        val header = request.header("Authorization") ?: return null
        if (!header.startsWith(BEARER)) return null
        if (priorResponses(response) >= 1) return null
        val rejected = header.removePrefix(BEARER)
        val fresh = try {
            runBlocking { tokens.refreshAfterUnauthorized(rejected) }
        } catch (e: MoonSsoException) {
            return null
        }
        if (fresh.accessToken == rejected) return null
        return request.newBuilder().header("Authorization", BEARER + fresh.accessToken).build()
    }

    private fun priorResponses(response: Response): Int {
        var n = 0
        var r = response.priorResponse
        while (r != null) {
            n++
            r = r.priorResponse
        }
        return n
    }
}
