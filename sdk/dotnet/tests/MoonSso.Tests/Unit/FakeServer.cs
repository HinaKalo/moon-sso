using System.Collections.Concurrent;
using System.Net;
using System.Text;
using System.Text.Json;
using MoonSso;

namespace MoonSso.Tests.Unit;

/// <summary>In-memory OAuth server double for deterministic unit tests of the token lifecycle.</summary>
internal sealed class FakeServer : HttpMessageHandler
{
    public const string Issuer = "https://sso.example.test";
    private int _counter;

    public ConcurrentQueue<HttpRequestMessage> TokenRequests { get; } = new();
    public ConcurrentQueue<string?> DPoPProofs { get; } = new();
    public ConcurrentQueue<string> TokenBodies { get; } = new();

    /// <summary>Scripted token endpoint responses (consumed in order); when empty, a fresh token set is issued.</summary>
    public ConcurrentQueue<Func<HttpResponseMessage>> TokenScript { get; } = new();

    public TimeSpan TokenDelay { get; set; }

    public string? LastRegistrationBody { get; private set; }

    public int ExpiresIn { get; set; } = 600;

    /// <summary>Access tokens accepted by the fake API (<c>/api/v1/me</c>).</summary>
    public ConcurrentDictionary<string, bool> ValidAccessTokens { get; } = new();

    public int TokenCalls => TokenRequests.Count;

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var path = request.RequestUri!.AbsolutePath;
        if (path == "/.well-known/openid-configuration")
        {
            return Json(200, new Dictionary<string, object>
            {
                ["issuer"] = Issuer,
                ["authorization_endpoint"] = Issuer + "/oauth/authorize",
                ["token_endpoint"] = Issuer + "/oauth/token",
                ["jwks_uri"] = Issuer + "/.well-known/jwks.json",
                ["revocation_endpoint"] = Issuer + "/oauth/revoke",
                ["registration_endpoint"] = Issuer + "/oauth/register",
                ["authorization_challenge_endpoint"] = Issuer + "/oauth/authorize-challenge",
                ["moon_events_endpoint"] = Issuer + "/api/v1/me/events",
                ["authorization_response_iss_parameter_supported"] = true,
            });
        }
        if (path == "/oauth/token")
        {
            TokenRequests.Enqueue(request);
            DPoPProofs.Enqueue(request.Headers.TryGetValues("DPoP", out var v) ? v.First() : null);
            TokenBodies.Enqueue(await request.Content!.ReadAsStringAsync(cancellationToken));
            if (TokenDelay > TimeSpan.Zero)
            {
                await Task.Delay(TokenDelay, cancellationToken);
            }
            if (TokenScript.TryDequeue(out var scripted))
            {
                return scripted();
            }
            return IssueTokens();
        }
        if (path == "/oauth/register")
        {
            LastRegistrationBody = await request.Content!.ReadAsStringAsync(cancellationToken);
            if (request.Headers.Authorization?.Parameter != "iat_good")
            {
                return Json(401, new { error = "invalid_token", error_description = "bad initial access token" });
            }
            return Json(201, new { client_id = "dcr-1", registration_access_token = "rat", registration_client_uri = Issuer + "/oauth/register/dcr-1", status = "pending_approval", client_name = "x", redirect_uris = new[] { "http://127.0.0.1/callback" }, token_endpoint_auth_method = "none" });
        }
        if (path == "/oauth/revoke")
        {
            return new HttpResponseMessage(HttpStatusCode.OK);
        }
        if (path == "/api/v1/me")
        {
            var auth = request.Headers.Authorization?.Parameter;
            if (auth is null || !ValidAccessTokens.ContainsKey(auth))
            {
                return Json(401, new { error = "invalid_token", error_description = "expired" });
            }
            var r = Json(200, new { sub = "user-1", preferred_username = "alice", name = "Alice", nickname = "", picture = (string?)null, updated_at = 1, profile_version = 2, totp_enabled = false });
            r.Headers.ETag = new System.Net.Http.Headers.EntityTagHeaderValue("\"pv-2\"");
            return r;
        }
        return new HttpResponseMessage(HttpStatusCode.NotFound);
    }

    public HttpResponseMessage IssueTokens()
    {
        var n = Interlocked.Increment(ref _counter);
        var at = $"at-{n}";
        ValidAccessTokens[at] = true;
        var r = Json(200, new { access_token = at, token_type = "Bearer", expires_in = ExpiresIn, refresh_token = $"rt-{n}", scope = "openid profile offline_access" });
        r.Headers.TryAddWithoutValidation("DPoP-Nonce", $"nonce-{n}");
        return r;
    }

    public static HttpResponseMessage Json(int status, object body, string? dpopNonce = null)
    {
        var r = new HttpResponseMessage((HttpStatusCode)status)
        {
            Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json"),
        };
        if (dpopNonce is not null)
        {
            r.Headers.TryAddWithoutValidation("DPoP-Nonce", dpopNonce);
        }
        return r;
    }

    public static StoredSession Session(string at = "at-0", string rt = "rt-0", DateTimeOffset? issuedAt = null, int lifetimeSeconds = 600, DPoPKeyData? key = null)
    {
        var iat = issuedAt ?? DateTimeOffset.UtcNow;
        return new StoredSession
        {
            Tokens = new TokenSet { AccessToken = at, RefreshToken = rt, IssuedAt = iat, ExpiresAt = iat.AddSeconds(lifetimeSeconds), Scope = "openid profile offline_access" },
            DPoPKey = key,
        };
    }

    public MoonSsoClient CreateClient(ITokenStore store, IRefreshLock? refreshLock = null, TimeProvider? time = null, bool dpop = true)
    {
        return new MoonSsoClient(new MoonSsoOptions
        {
            Issuer = Issuer,
            ClientId = "test-client",
            HttpHandler = this,
            TokenStore = store,
            RefreshLock = refreshLock,
            UseDPoP = dpop,
            AutoRefresh = false,
            TimeProvider = time ?? TimeProvider.System,
        });
    }
}
