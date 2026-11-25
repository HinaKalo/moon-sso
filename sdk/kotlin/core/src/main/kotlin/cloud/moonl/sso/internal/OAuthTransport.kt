package cloud.moonl.sso.internal

import cloud.moonl.sso.MoonSsoException
import cloud.moonl.sso.MoonSsoLogger
import cloud.moonl.sso.debug
import cloud.moonl.sso.dpop.DpopProofs
import okhttp3.FormBody
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.IOException
import java.net.ConnectException
import java.net.UnknownHostException

/** When a form POST is repeated after a transport failure or a 502/503/504 response. */
internal enum class RetryPolicy {
    /** Never repeat (non-idempotent requests such as registration). */
    NONE,

    /** Repeat only when the request certainly did not reach the server, or it answered 503. */
    SAFE,

    /** Repeat once on any network error, connection reset, 502, 503 or 504 (refresh grant). */
    TRANSIENT,
}

/**
 * Form POSTs to the OAuth endpoints with DPoP proofs, nonce handling (`use_dpop_nonce` → one
 * immediate retry with the new nonce) and the retry rules of the SDK specification.
 */
internal class OAuthTransport(
    private val http: OkHttpClient,
    private val dpop: DpopProofs?,
    private val logger: MoonSsoLogger,
) {
    /**
     * Returns the final response (successful or not). Transport failures throw `network`.
     * [dpopHtu] is the `htu` claim of the DPoP proof (defaults to [url]).
     */
    suspend fun postForm(url: String, form: Map<String, String>, retry: RetryPolicy, dpopHtu: String = url): HttpResult {
        var networkRetried = false
        var nonceRetried = false
        while (true) {
            val body = FormBody.Builder().apply { form.forEach { (k, v) -> add(k, v) } }.build()
            val request = Request.Builder()
                .url(url)
                .header("Accept", "application/json")
                .post(body)
                .apply { dpop?.let { header("DPoP", it.proof("POST", dpopHtu)) } }
                .build()
            val result = try {
                http.newCall(request).awaitResult()
            } catch (e: IOException) {
                if (!networkRetried && retryable(e, retry)) {
                    networkRetried = true
                    logger.debug("retrying ${request.url.encodedPath} after ${e.javaClass.simpleName}")
                    continue
                }
                throw networkError(e)
            }
            dpop?.observe(result.headers)
            if (!networkRetried && retryableStatus(result.code, retry)) {
                networkRetried = true
                logger.debug("retrying ${request.url.encodedPath} after HTTP ${result.code}")
                continue
            }
            if (dpop != null && !nonceRetried && result.code in 400..401) {
                val err = result.string(result.json(), "error")
                if (err == "use_dpop_nonce" && result.headers["DPoP-Nonce"] != null) {
                    nonceRetried = true
                    continue
                }
            }
            return result
        }
    }

    private fun retryable(e: IOException, policy: RetryPolicy): Boolean = when (policy) {
        RetryPolicy.NONE -> false
        RetryPolicy.SAFE -> e is ConnectException || e is UnknownHostException
        RetryPolicy.TRANSIENT -> true
    }

    private fun retryableStatus(code: Int, policy: RetryPolicy): Boolean = when (policy) {
        RetryPolicy.NONE -> false
        RetryPolicy.SAFE -> code == 503
        RetryPolicy.TRANSIENT -> code == 502 || code == 503 || code == 504
    }
}

/** Throws [MoonSsoException] for non-2xx results. */
internal fun HttpResult.orThrow(): HttpResult = requireSuccess()

internal fun requireEndpoint(value: String?, name: String): String =
    value ?: throw MoonSsoException(MoonSsoException.INVALID_RESPONSE, "discovery document has no $name")
