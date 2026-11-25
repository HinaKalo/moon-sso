using System.Collections.Concurrent;
using System.Text.Json;
using MoonSso.Internal;

namespace MoonSso;

/// <summary>A validated OpenID Connect Back-Channel Logout request.</summary>
public sealed record BackchannelLogoutRequest(string? Subject, string? SessionId, string JwtId, JwtClaims Claims);

/// <summary>
/// Validates <c>logout_token</c>s (OpenID Connect Back-Channel Logout 1.0) for server-side apps: signature via JWKS,
/// <c>typ == logout+jwt</c>, <c>iss</c>, <c>aud</c> contains the client_id, <c>iat</c> ≤ now + 60 s, <c>exp</c>, the back-channel
/// logout event, <c>sub</c> or <c>sid</c>, no <c>nonce</c>, and <c>jti</c> replay protection for 5 minutes.
/// </summary>
public sealed class BackchannelLogoutVerifier
{
    private const string LogoutEvent = "http://schemas.openid.net/event/backchannel-logout";
    private static readonly TimeSpan ReplayWindow = TimeSpan.FromMinutes(5);

    private readonly TokenValidator _validator;
    private readonly string _clientId;
    private readonly ConcurrentDictionary<string, DateTimeOffset> _seen = new(StringComparer.Ordinal);
    private long _lastSweep;

    public BackchannelLogoutVerifier(TokenValidator validator, string clientId)
    {
        _validator = validator ?? throw new ArgumentNullException(nameof(validator));
        ArgumentException.ThrowIfNullOrEmpty(clientId);
        _clientId = clientId;
    }

    /// <summary>Uses the validator of an existing client.</summary>
    public BackchannelLogoutVerifier(MoonSsoClient client)
        : this((client ?? throw new ArgumentNullException(nameof(client))).Validator, client.Options.ClientId)
    {
    }

    /// <summary>
    /// Validates the token. On success, sign out the user/session and answer HTTP 200; on <see cref="MoonSsoException"/> answer 400.
    /// </summary>
    public async Task<BackchannelLogoutRequest> ValidateAsync(string logoutToken, CancellationToken cancellationToken = default)
    {
        const string code = "invalid_request";
        if (string.IsNullOrEmpty(logoutToken))
        {
            throw new MoonSsoException(code, "Missing logout_token.");
        }
        var claims = await _validator.VerifySignatureAsync(logoutToken, code, cancellationToken).ConfigureAwait(false);
        if (claims.Token.Typ != "logout+jwt")
        {
            throw new MoonSsoException(code, "logout_token typ must be logout+jwt.");
        }
        _validator.CheckIssuer(claims, code);
        if (!claims.Audiences.Contains(_clientId))
        {
            throw new MoonSsoException(code, "logout_token audience does not contain this client.");
        }
        var now = _validator.UtcNow;
        var nowS = now.ToUnixTimeSeconds();
        if (claims.IssuedAt is not { } iat || iat > nowS + 60)
        {
            throw new MoonSsoException(code, "logout_token iat is missing or in the future.");
        }
        if (claims.ExpiresAt is { } exp && nowS - (long)_validator.ClockSkew.TotalSeconds >= exp)
        {
            throw new MoonSsoException(code, "logout_token expired.");
        }
        if (!claims.TryGetProperty("events", out var events) || events.ValueKind != JsonValueKind.Object || !events.TryGetProperty(LogoutEvent, out var ev) || ev.ValueKind != JsonValueKind.Object)
        {
            throw new MoonSsoException(code, "logout_token has no back-channel logout event.");
        }
        if (claims.Subject is null && claims.SessionId is null)
        {
            throw new MoonSsoException(code, "logout_token needs sub or sid.");
        }
        if (claims.TryGetProperty("nonce", out _))
        {
            throw new MoonSsoException(code, "logout_token must not contain a nonce.");
        }
        var jti = claims.JwtId;
        if (string.IsNullOrEmpty(jti))
        {
            throw new MoonSsoException(code, "logout_token has no jti.");
        }
        Sweep(now);
        if (!_seen.TryAdd(jti, now + ReplayWindow))
        {
            throw new MoonSsoException(code, "logout_token was already used.");
        }
        return new BackchannelLogoutRequest(claims.Subject, claims.SessionId, jti, claims);
    }

    private void Sweep(DateTimeOffset now)
    {
        var last = Interlocked.Read(ref _lastSweep);
        if (now.ToUnixTimeSeconds() - last < 30 || Interlocked.CompareExchange(ref _lastSweep, now.ToUnixTimeSeconds(), last) != last)
        {
            return;
        }
        foreach (var kv in _seen)
        {
            if (kv.Value < now)
            {
                _seen.TryRemove(kv.Key, out _);
            }
        }
    }
}
