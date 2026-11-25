package cloud.moonl.sso.internal

import cloud.moonl.sso.DiscoveryClient
import cloud.moonl.sso.MoonSsoConfig
import cloud.moonl.sso.MoonSsoException
import cloud.moonl.sso.OtpChallenge
import cloud.moonl.sso.OtpRequiredException
import cloud.moonl.sso.PasswordChangeRequiredException
import cloud.moonl.sso.PendingAuthorization
import cloud.moonl.sso.Pkce
import cloud.moonl.sso.SecureTokens
import cloud.moonl.sso.TokenManager
import cloud.moonl.sso.TokenSet
import cloud.moonl.sso.dpop.DpopProofs
import cloud.moonl.sso.jwt.constantTimeEquals
import okhttp3.HttpUrl.Companion.toHttpUrl
import java.net.URLDecoder

/** First-party login (`/oauth/authorize-challenge`), OTP step and native registration. */
internal class FirstPartyLogin(
    private val config: MoonSsoConfig,
    private val discovery: DiscoveryClient,
    private val transport: OAuthTransport,
    private val tokens: TokenManager,
    private val dpop: Boolean,
) {
    suspend fun signIn(username: String, password: String, scope: String): TokenSet {
        require(username.isNotBlank() && password.isNotEmpty()) { "username and password are required" }
        val pkce = Pkce.generate()
        val result = transport.postForm(
            challengeEndpoint(),
            mapOf(
                "client_id" to config.clientId,
                "username" to username,
                "password" to password,
                "scope" to scope,
                "code_challenge" to pkce.codeChallenge,
                "code_challenge_method" to "S256",
            ),
            RetryPolicy.NONE,
        )
        return handle(result, pkce, scope)
    }

    suspend fun submitOtp(challenge: OtpChallenge, otp: String): TokenSet {
        val code = otp.trim()
        require(code.isNotEmpty()) { "otp is required" }
        val result = transport.postForm(
            challengeEndpoint(),
            mapOf(
                "client_id" to config.clientId,
                "auth_session" to challenge.authSession,
                "otp" to code,
                "scope" to challenge.scope,
                "code_challenge" to challenge.pkce.codeChallenge,
                "code_challenge_method" to "S256",
            ),
            RetryPolicy.NONE,
        )
        return handle(result, challenge.pkce, challenge.scope)
    }

    suspend fun register(username: String, password: String, displayName: String?, scope: String): TokenSet {
        val pkce = Pkce.generate()
        val form = buildMap {
            put("client_id", config.clientId)
            put("username", username)
            put("password", password)
            if (!displayName.isNullOrBlank()) put("display_name", displayName)
            put("scope", scope)
            put("code_challenge", pkce.codeChallenge)
            put("code_challenge_method", "S256")
        }
        val registerUrl = "${config.issuer}/api/v1/native/register"
        // The server verifies native-registration proofs against the authorize-challenge URL
        // (oidc.parseChallengeReq), while the SDK spec says htu is the registration URL. Send what the
        // server accepts; if it rejects the proof (a corrected server), repeat once with the spec'd htu.
        // A rejected proof is checked before any account is created, so the repeat is safe.
        var result = transport.postForm(registerUrl, form, RetryPolicy.NONE, dpopHtu = challengeEndpoint())
        if (dpop && result.code == 400 && result.string(result.json(), "error") == "invalid_dpop_proof") {
            result = transport.postForm(registerUrl, form, RetryPolicy.NONE, dpopHtu = registerUrl)
        }
        if (result.code == 403) {
            // The server answers access_denied; the SDK contract calls this registration_closed.
            val e = result.toError()
            throw MoonSsoException("registration_closed", e.errorDescription, 403)
        }
        return handle(result, pkce, scope)
    }

    private suspend fun challengeEndpoint(): String =
        discovery.get().authorizationChallengeEndpoint ?: "${config.issuer}/oauth/authorize-challenge"

    private suspend fun handle(result: HttpResult, pkce: Pkce, scope: String): TokenSet {
        val obj = result.json()
        if (result.isSuccessful) {
            val code = result.string(obj, "authorization_code")
                ?: throw MoonSsoException(MoonSsoException.INVALID_RESPONSE, "response has no authorization_code", result.code)
            return tokens.exchangeCode(code, pkce.codeVerifier, redirectUri = null, expectedNonce = null)
        }
        when (result.string(obj, "error")) {
            "insufficient_authorization" -> {
                val session = result.string(obj, "auth_session")
                if (session != null) {
                    val required = result.string(obj, "required") ?: "otp"
                    throw OtpRequiredException(OtpChallenge(session, required, pkce, scope), result.string(obj, "error_description"))
                }
            }
            "password_change_required" ->
                throw PasswordChangeRequiredException(result.string(obj, "change_url"), result.string(obj, "error_description"))
        }
        throw result.toError()
    }
}

/** Browser authorization code flow (system browser / Custom Tabs). */
internal class BrowserAuthorization(
    private val config: MoonSsoConfig,
    private val discovery: DiscoveryClient,
    private val tokens: TokenManager,
    private val dpop: DpopProofs?,
    private val clock: () -> Long,
) {
    suspend fun create(
        redirectUri: String,
        scope: String,
        prompt: String?,
        loginHint: String?,
        extraParameters: Map<String, String>,
    ): PendingAuthorization {
        val doc = discovery.get()
        val pkce = Pkce.generate()
        val state = SecureTokens.token(32)
        val nonce = SecureTokens.token(32)
        val url = doc.authorizationEndpoint.toHttpUrl().newBuilder().apply {
            extraParameters.forEach { (k, v) -> addQueryParameter(k, v) }
            setQueryParameter("client_id", config.clientId)
            setQueryParameter("redirect_uri", redirectUri)
            setQueryParameter("response_type", "code")
            setQueryParameter("scope", scope)
            setQueryParameter("state", state)
            setQueryParameter("nonce", nonce)
            setQueryParameter("code_challenge", pkce.codeChallenge)
            setQueryParameter("code_challenge_method", "S256")
            dpop?.let { setQueryParameter("dpop_jkt", it.key().thumbprint) }
            prompt?.let { setQueryParameter("prompt", it) }
            loginHint?.let { setQueryParameter("login_hint", it) }
        }.build()
        return PendingAuthorization(
            authorizationUrl = url.toString(),
            redirectUri = redirectUri,
            state = state,
            nonce = nonce,
            codeVerifier = pkce.codeVerifier,
            scope = scope,
            createdAt = clock() / 1000,
        )
    }

    suspend fun complete(pending: PendingAuthorization, callbackUri: String): TokenSet {
        val base = callbackUri.substringBefore('#').substringBefore('?')
        if (base != pending.redirectUri) {
            throw MoonSsoException(MoonSsoException.STATE_MISMATCH, "callback does not belong to this authorization request")
        }
        val params = parseCallbackParameters(callbackUri)
        if (!constantTimeEquals(params["state"], pending.state)) {
            throw MoonSsoException(MoonSsoException.STATE_MISMATCH, "state parameter does not match")
        }
        val iss = params["iss"]
        val doc = discovery.get()
        if (iss == null && doc.issParameterSupported) {
            throw MoonSsoException(MoonSsoException.INVALID_RESPONSE, "authorization response has no iss parameter")
        }
        if (iss != null && iss.trimEnd('/') != config.issuer) {
            throw MoonSsoException(MoonSsoException.INVALID_RESPONSE, "authorization response iss does not match the issuer")
        }
        params["error"]?.let { throw MoonSsoException(it, params["error_description"]) }
        val code = params["code"] ?: throw MoonSsoException(MoonSsoException.INVALID_RESPONSE, "authorization response has no code")
        return tokens.exchangeCode(code, pending.codeVerifier, pending.redirectUri, pending.nonce)
    }

    companion object {
        /** Parses the query of a redirect URI (works for custom schemes such as `com.example.app:/oauth2redirect`). */
        fun parseCallbackParameters(uri: String): Map<String, String> {
            val query = uri.substringBefore('#').substringAfter('?', "")
            if (query.isEmpty()) return emptyMap()
            val out = LinkedHashMap<String, String>()
            for (part in query.split('&')) {
                if (part.isEmpty()) continue
                val k = URLDecoder.decode(part.substringBefore('='), "UTF-8")
                val v = URLDecoder.decode(part.substringAfter('=', ""), "UTF-8")
                if (!out.containsKey(k)) out[k] = v
            }
            return out
        }
    }
}
