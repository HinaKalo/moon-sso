using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Serialization;
using MoonSso.Internal;

namespace MoonSso;

/// <summary>Client metadata for dynamic client registration (RFC 7591).</summary>
public sealed record ClientRegistrationRequest
{
    [JsonPropertyName("client_name")] public string ClientName { get; init; } = "";
    [JsonPropertyName("redirect_uris")] public IReadOnlyList<string> RedirectUris { get; init; } = Array.Empty<string>();
    [JsonPropertyName("post_logout_redirect_uris")] public IReadOnlyList<string>? PostLogoutRedirectUris { get; init; }
    [JsonPropertyName("grant_types")] public IReadOnlyList<string>? GrantTypes { get; init; }
    /// <summary><c>client_secret_basic</c>, <c>client_secret_post</c> or <c>none</c>.</summary>
    [JsonPropertyName("token_endpoint_auth_method")] public string? TokenEndpointAuthMethod { get; init; }
    /// <summary><c>web</c> or <c>native</c>.</summary>
    [JsonPropertyName("application_type")] public string? ApplicationType { get; init; }
    [JsonPropertyName("scope")] public string? Scope { get; init; }
    [JsonPropertyName("id_token_signed_response_alg")] public string? IdTokenSignedResponseAlg { get; init; }
    [JsonPropertyName("backchannel_logout_uri")] public string? BackchannelLogoutUri { get; init; }
    [JsonPropertyName("dpop_bound_access_tokens")] public bool? DPoPBoundAccessTokens { get; init; }
    [JsonPropertyName("webhook_url")] public string? WebhookUrl { get; init; }
    [JsonPropertyName("webhook_events")] public IReadOnlyList<string>? WebhookEvents { get; init; }
    [JsonPropertyName("logo_uri")] public string? LogoUri { get; init; }
    [JsonPropertyName("client_uri")] public string? ClientUri { get; init; }
    [JsonPropertyName("policy_uri")] public string? PolicyUri { get; init; }
    [JsonPropertyName("tos_uri")] public string? TosUri { get; init; }
}

/// <summary>Registration response. Store <see cref="ClientSecret"/>, <see cref="RegistrationAccessToken"/> and <see cref="WebhookSecret"/> securely.</summary>
public sealed record ClientRegistrationResponse
{
    [JsonPropertyName("client_id")] public string ClientId { get; init; } = "";
    [JsonPropertyName("client_secret")] public string? ClientSecret { get; init; }
    [JsonPropertyName("registration_access_token")] public string? RegistrationAccessToken { get; init; }
    [JsonPropertyName("registration_client_uri")] public string? RegistrationClientUri { get; init; }
    [JsonPropertyName("webhook_secret")] public string? WebhookSecret { get; init; }
    /// <summary><c>active</c>, <c>pending_approval</c> or <c>disabled</c>.</summary>
    [JsonPropertyName("status")] public string? Status { get; init; }
    [JsonPropertyName("client_name")] public string? ClientName { get; init; }
    [JsonPropertyName("redirect_uris")] public IReadOnlyList<string>? RedirectUris { get; init; }
    [JsonPropertyName("token_endpoint_auth_method")] public string? TokenEndpointAuthMethod { get; init; }
    [JsonPropertyName("scope")] public string? Scope { get; init; }

    public override string ToString() => $"ClientRegistrationResponse {{ ClientId = {ClientId}, Status = {Status} }}";
}

/// <summary>Dynamic client registration helper (<c>POST /oauth/register</c> with an initial access token).</summary>
public static class DynamicClientRegistration
{
    /// <summary>Registers a client. <paramref name="initialAccessToken"/> comes from the developer center (<c>iat_...</c>).</summary>
    public static async Task<ClientRegistrationResponse> RegisterClientAsync(
        HttpClient http,
        string issuer,
        string initialAccessToken,
        ClientRegistrationRequest metadata,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentException.ThrowIfNullOrEmpty(initialAccessToken);
        ArgumentNullException.ThrowIfNull(metadata);
        var discovery = new DiscoveryCache(http, issuer);
        var doc = await discovery.GetAsync(cancellationToken).ConfigureAwait(false);
        var endpoint = doc.RegistrationEndpoint ?? discovery.Issuer + "/oauth/register";
        using var req = new HttpRequestMessage(HttpMethod.Post, endpoint)
        {
            Content = new ByteArrayContent(JsonSerializer.SerializeToUtf8Bytes(metadata, Json.Options)),
        };
        req.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", initialAccessToken);
        req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        if (req.Headers.UserAgent.Count == 0 && http.DefaultRequestHeaders.UserAgent.Count == 0)
        {
            req.Headers.UserAgent.ParseAdd(MoonSsoClient.UserAgent);
        }
        HttpResponseMessage resp;
        try
        {
            resp = await http.SendAsync(req, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (OAuthTransport.IsNetworkFailure(ex, cancellationToken))
        {
            throw new MoonSsoException(ErrorCodes.Network, "Client registration request failed.", innerException: ex);
        }
        using (resp)
        {
            var body = await OAuthTransport.ReadJsonAsync(resp, cancellationToken).ConfigureAwait(false);
            var result = new OAuthResponse((int)resp.StatusCode, body);
            if (!result.IsSuccess)
            {
                throw result.ToException();
            }
            return Json.Deserialize<ClientRegistrationResponse>(body);
        }
    }

    /// <summary>Registers a client using the HTTP stack of an existing <see cref="MoonSsoClient"/>.</summary>
    public static Task<ClientRegistrationResponse> RegisterClientAsync(this MoonSsoClient client, string initialAccessToken, ClientRegistrationRequest metadata, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(client);
        return RegisterClientAsync(client.RawHttp, client.Options.Issuer, initialAccessToken, metadata, cancellationToken);
    }
}
