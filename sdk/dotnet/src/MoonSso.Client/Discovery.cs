using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Serialization;
using MoonSso.Internal;

namespace MoonSso;

/// <summary>OpenID Provider metadata (<c>/.well-known/openid-configuration</c>).</summary>
public sealed record DiscoveryDocument
{
    [JsonPropertyName("issuer")] public string Issuer { get; init; } = "";
    [JsonPropertyName("authorization_endpoint")] public string AuthorizationEndpoint { get; init; } = "";
    [JsonPropertyName("token_endpoint")] public string TokenEndpoint { get; init; } = "";
    [JsonPropertyName("userinfo_endpoint")] public string? UserinfoEndpoint { get; init; }
    [JsonPropertyName("jwks_uri")] public string JwksUri { get; init; } = "";
    [JsonPropertyName("registration_endpoint")] public string? RegistrationEndpoint { get; init; }
    [JsonPropertyName("revocation_endpoint")] public string? RevocationEndpoint { get; init; }
    [JsonPropertyName("introspection_endpoint")] public string? IntrospectionEndpoint { get; init; }
    [JsonPropertyName("end_session_endpoint")] public string? EndSessionEndpoint { get; init; }
    [JsonPropertyName("authorization_challenge_endpoint")] public string? AuthorizationChallengeEndpoint { get; init; }
    [JsonPropertyName("moon_events_endpoint")] public string? EventsEndpoint { get; init; }
    [JsonPropertyName("moon_api_audience")] public string? ApiAudience { get; init; }
    [JsonPropertyName("scopes_supported")] public IReadOnlyList<string>? ScopesSupported { get; init; }
    [JsonPropertyName("dpop_signing_alg_values_supported")] public IReadOnlyList<string>? DPoPSigningAlgValuesSupported { get; init; }
    [JsonPropertyName("id_token_signing_alg_values_supported")] public IReadOnlyList<string>? IdTokenSigningAlgValuesSupported { get; init; }
    [JsonPropertyName("authorization_response_iss_parameter_supported")] public bool AuthorizationResponseIssParameterSupported { get; init; }

    /// <summary>Base URL of the account API (<c>{issuer}/api/v1</c>).</summary>
    [JsonIgnore] public string ApiBase => Issuer.TrimEnd('/') + "/api/v1";
}

/// <summary>
/// Fetches and caches the discovery document for one hour. When a refetch fails the stale document keeps being used.
/// </summary>
public sealed class DiscoveryCache
{
    private static readonly TimeSpan Ttl = TimeSpan.FromHours(1);
    private readonly HttpClient _http;
    private readonly string _issuer;
    private readonly TimeProvider _time;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private DiscoveryDocument? _doc;
    private DateTimeOffset _fetchedAt;

    public DiscoveryCache(HttpClient http, string issuer, TimeProvider? timeProvider = null)
    {
        _http = http ?? throw new ArgumentNullException(nameof(http));
        _issuer = NormalizeIssuer(issuer);
        _time = timeProvider ?? TimeProvider.System;
    }

    public string Issuer => _issuer;

    internal static string NormalizeIssuer(string issuer)
    {
        if (string.IsNullOrWhiteSpace(issuer) || !Uri.TryCreate(issuer, UriKind.Absolute, out var u) || (u.Scheme != Uri.UriSchemeHttps && u.Scheme != Uri.UriSchemeHttp))
        {
            throw new ArgumentException("Issuer must be an absolute http(s) URL.", nameof(issuer));
        }
        return issuer.TrimEnd('/');
    }

    public async Task<DiscoveryDocument> GetAsync(CancellationToken cancellationToken = default)
    {
        var doc = _doc;
        if (doc is not null && _time.GetUtcNow() - _fetchedAt < Ttl)
        {
            return doc;
        }
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            doc = _doc;
            if (doc is not null && _time.GetUtcNow() - _fetchedAt < Ttl)
            {
                return doc;
            }
            try
            {
                doc = await FetchAsync(cancellationToken).ConfigureAwait(false);
                _doc = doc;
                _fetchedAt = _time.GetUtcNow();
                return doc;
            }
            catch (MoonSsoException) when (_doc is not null && !cancellationToken.IsCancellationRequested)
            {
                // Keep using the stale document; try again in a minute rather than on every call.
                _fetchedAt = _time.GetUtcNow() - Ttl + TimeSpan.FromMinutes(1);
                return _doc;
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task<DiscoveryDocument> FetchAsync(CancellationToken ct)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, _issuer + "/.well-known/openid-configuration");
        req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        HttpResponseMessage resp;
        try
        {
            resp = await _http.SendAsync(req, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException || (ex is TaskCanceledException && !ct.IsCancellationRequested))
        {
            throw new MoonSsoException(ErrorCodes.Network, "Discovery request failed.", innerException: ex);
        }
        using (resp)
        {
            if (!resp.IsSuccessStatusCode)
            {
                throw new MoonSsoException(resp.StatusCode >= System.Net.HttpStatusCode.InternalServerError ? ErrorCodes.Network : ErrorCodes.InvalidResponse,
                    "Discovery request failed.", (int)resp.StatusCode);
            }
            DiscoveryDocument? doc;
            try
            {
                await using var s = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
                doc = await JsonSerializer.DeserializeAsync<DiscoveryDocument>(s, Json.Options, ct).ConfigureAwait(false);
            }
            catch (JsonException ex)
            {
                throw new MoonSsoException(ErrorCodes.InvalidResponse, "Malformed discovery document.", (int)resp.StatusCode, innerException: ex);
            }
            if (doc is null || doc.Issuer.TrimEnd('/') != _issuer || string.IsNullOrEmpty(doc.TokenEndpoint) || string.IsNullOrEmpty(doc.JwksUri))
            {
                throw new MoonSsoException(ErrorCodes.InvalidResponse, "Discovery document issuer mismatch or missing endpoints.", (int)resp.StatusCode);
            }
            return doc;
        }
    }
}
