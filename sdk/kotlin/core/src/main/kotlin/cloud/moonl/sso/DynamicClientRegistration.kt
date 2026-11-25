package cloud.moonl.sso

import cloud.moonl.sso.internal.SdkJson
import cloud.moonl.sso.internal.UserAgentInterceptor
import cloud.moonl.sso.internal.decode
import cloud.moonl.sso.internal.requireEndpoint
import cloud.moonl.sso.internal.requireSuccess
import cloud.moonl.sso.internal.send
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

/** RFC 7591 client metadata accepted by `POST /oauth/register`. */
@Serializable
public data class ClientMetadata(
    @SerialName("client_name") val clientName: String,
    @SerialName("redirect_uris") val redirectUris: List<String>,
    @SerialName("post_logout_redirect_uris") val postLogoutRedirectUris: List<String>? = null,
    @SerialName("grant_types") val grantTypes: List<String>? = null,
    @SerialName("token_endpoint_auth_method") val tokenEndpointAuthMethod: String? = null,
    @SerialName("application_type") val applicationType: String? = null,
    val scope: String? = null,
    @SerialName("id_token_signed_response_alg") val idTokenSignedResponseAlg: String? = null,
    @SerialName("backchannel_logout_uri") val backchannelLogoutUri: String? = null,
    @SerialName("dpop_bound_access_tokens") val dpopBoundAccessTokens: Boolean? = null,
    @SerialName("webhook_url") val webhookUrl: String? = null,
    @SerialName("webhook_events") val webhookEvents: List<String>? = null,
    @SerialName("logo_uri") val logoUri: String? = null,
    @SerialName("client_uri") val clientUri: String? = null,
    @SerialName("policy_uri") val policyUri: String? = null,
    @SerialName("tos_uri") val tosUri: String? = null,
)

/** Response of a successful registration. Secrets are redacted from [toString]. */
@Serializable
public data class ClientRegistration(
    @SerialName("client_id") val clientId: String,
    @SerialName("client_secret") val clientSecret: String? = null,
    @SerialName("registration_access_token") val registrationAccessToken: String? = null,
    @SerialName("registration_client_uri") val registrationClientUri: String? = null,
    @SerialName("webhook_secret") val webhookSecret: String? = null,
    /** `active` or `pending_approval`. */
    val status: String? = null,
    @SerialName("client_name") val clientName: String? = null,
    @SerialName("redirect_uris") val redirectUris: List<String> = emptyList(),
    @SerialName("token_endpoint_auth_method") val tokenEndpointAuthMethod: String? = null,
    @SerialName("application_type") val applicationType: String? = null,
    val scope: String? = null,
) {
    override fun toString(): String =
        "ClientRegistration(clientId=$clientId, status=$status, clientName=$clientName, applicationType=$applicationType, " +
            "clientSecret=${if (clientSecret != null) "<redacted>" else "null"})"
}

/** Dynamic client registration (RFC 7591) with an initial access token from the developer center. */
public class DynamicClientRegistration(
    issuer: String,
    httpClient: OkHttpClient = OkHttpClient(),
    userAgent: String = MoonSsoConfig.DEFAULT_USER_AGENT,
) {
    private val issuer = issuer.trimEnd('/')
    private val http = httpClient.newBuilder().addInterceptor(UserAgentInterceptor(userAgent)).build()
    private val discovery = DiscoveryClient(this.issuer, http, System::currentTimeMillis)

    /** Registers a client. Returns `client_id`, `client_secret?`, `registration_access_token` and `status`. */
    public suspend fun registerClient(initialAccessToken: String, metadata: ClientMetadata): ClientRegistration {
        val endpoint = requireEndpoint(discovery.get().registrationEndpoint, "registration_endpoint")
        val body = SdkJson.encodeToString(ClientMetadata.serializer(), metadata)
        val req = Request.Builder()
            .url(endpoint)
            .header("Authorization", "Bearer $initialAccessToken")
            .header("Accept", "application/json")
            .post(body.toRequestBody("application/json; charset=utf-8".toMediaType()))
            .build()
        return http.send(req).requireSuccess().decode<ClientRegistration>()
    }

    /** Deletes a registered client (RFC 7592) with its registration access token. */
    public suspend fun deleteClient(registration: ClientRegistration) {
        val token = registration.registrationAccessToken
            ?: throw IllegalArgumentException("registration has no registration_access_token")
        val uri = registration.registrationClientUri
            ?: (requireEndpoint(discovery.get().registrationEndpoint, "registration_endpoint") + "/" + registration.clientId)
        val req = Request.Builder()
            .url(uri)
            .header("Authorization", "Bearer $token")
            .delete()
            .build()
        http.send(req).requireSuccess()
    }
}
