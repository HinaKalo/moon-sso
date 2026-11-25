using System.Text.Json;
using System.Text.Json.Serialization;

namespace MoonSso;

/// <summary>Tokens of a signed-in session. <see cref="ExpiresAt"/> is computed locally as now + expires_in.</summary>
public sealed record TokenSet
{
    [JsonPropertyName("access_token")] public string AccessToken { get; init; } = "";
    [JsonPropertyName("token_type")] public string TokenType { get; init; } = "Bearer";
    [JsonPropertyName("refresh_token")] public string? RefreshToken { get; init; }
    [JsonPropertyName("id_token")] public string? IdToken { get; init; }
    [JsonPropertyName("scope")] public string? Scope { get; init; }
    /// <summary>Local time the tokens were received.</summary>
    [JsonPropertyName("issued_at")] public DateTimeOffset IssuedAt { get; init; }
    /// <summary>Local expiry of the access token.</summary>
    [JsonPropertyName("expires_at")] public DateTimeOffset ExpiresAt { get; init; }

    /// <summary>Lifetime of the access token as granted by the server.</summary>
    [JsonIgnore] public TimeSpan Lifetime => ExpiresAt - IssuedAt;

    /// <summary>Scopes as a set.</summary>
    [JsonIgnore]
    public IReadOnlyCollection<string> Scopes =>
        (Scope ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    public override string ToString() => $"TokenSet {{ TokenType = {TokenType}, Scope = {Scope}, ExpiresAt = {ExpiresAt:O} }}";
}

/// <summary>The current user's profile as seen by this client (<c>GET /api/v1/me</c>).</summary>
public sealed record UserProfile
{
    [JsonPropertyName("sub")] public string Sub { get; init; } = "";
    [JsonPropertyName("preferred_username")] public string? PreferredUsername { get; init; }
    [JsonPropertyName("name")] public string? Name { get; init; }
    [JsonPropertyName("nickname")] public string? Nickname { get; init; }
    [JsonPropertyName("picture")] public string? Picture { get; init; }
    /// <summary>Unix seconds of the last profile change.</summary>
    [JsonPropertyName("updated_at")] public long UpdatedAt { get; init; }
    [JsonPropertyName("profile_version")] public long ProfileVersion { get; init; }
    [JsonPropertyName("totp_enabled")] public bool? TotpEnabled { get; init; }
}

/// <summary>A profile event, delivered identically by SSE, webhooks and the changes feed.</summary>
public sealed record ProfileEvent
{
    [JsonPropertyName("id")] public string? Id { get; init; }
    [JsonPropertyName("seq")] public long Seq { get; init; }
    [JsonPropertyName("type")] public string Type { get; init; } = "";
    [JsonPropertyName("occurred_at")] public DateTimeOffset? OccurredAt { get; init; }
    [JsonPropertyName("data")] public ProfileEventData? Data { get; init; }
}

/// <summary>Payload of a <see cref="ProfileEvent"/>.</summary>
public sealed record ProfileEventData
{
    [JsonPropertyName("sub")] public string? Sub { get; init; }
    [JsonPropertyName("status")] public string? Status { get; init; }
    [JsonPropertyName("preferred_username")] public string? PreferredUsername { get; init; }
    [JsonPropertyName("name")] public string? Name { get; init; }
    [JsonPropertyName("nickname")] public string? Nickname { get; init; }
    [JsonPropertyName("picture")] public string? Picture { get; init; }
    [JsonPropertyName("profile_version")] public long ProfileVersion { get; init; }
    [JsonPropertyName("updated_at")] public long UpdatedAt { get; init; }
    [JsonPropertyName("changed")] public IReadOnlyList<string>? Changed { get; init; }
}

/// <summary>Well-known event types.</summary>
public static class EventTypes
{
    public const string UserUpdated = "user.updated";
    public const string UserPasswordChanged = "user.password_changed";
    public const string UserDisabled = "user.disabled";
    public const string UserEnabled = "user.enabled";
    public const string UserDeleted = "user.deleted";
    public const string ConsentRevoked = "consent.revoked";
    public const string Resync = "resync";
    public const string TokenExpired = "token_expired";
}

/// <summary>Fields to change with <see cref="MoonSsoClient.UpdateProfileAsync"/>. Null means unchanged.</summary>
public sealed record ProfileUpdate
{
    [JsonPropertyName("username")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Username { get; init; }

    [JsonPropertyName("display_name")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? DisplayName { get; init; }

    /// <summary>When set, sends <c>If-Match: "pv-&lt;n&gt;"</c>; the server answers 412 <c>version_conflict</c> if the profile changed meanwhile.</summary>
    [JsonIgnore] public long? IfMatchVersion { get; init; }
}

/// <summary>Self-service registration settings (<c>GET /api/v1/registration</c>).</summary>
public sealed record RegistrationInfo
{
    [JsonPropertyName("registration_open")] public bool RegistrationOpen { get; init; }
    [JsonPropertyName("password_min_length")] public int PasswordMinLength { get; init; }
    [JsonPropertyName("username_pattern")] public string? UsernamePattern { get; init; }
    [JsonPropertyName("client_registration")] public JsonElement? ClientRegistration { get; init; }
}

/// <summary>Input for in-app registration.</summary>
public sealed record NativeRegistration(string Username, string Password, string? DisplayName = null, string? Scope = null);

/// <summary>Pending second-factor step of a first-party login.</summary>
public sealed class OtpChallenge
{
    internal OtpChallenge(string authSession, string codeVerifier, string scope)
    {
        AuthSession = authSession;
        CodeVerifier = codeVerifier;
        Scope = scope;
    }

    /// <summary>Opaque server session for the OTP step (valid for 5 minutes).</summary>
    public string AuthSession { get; }

    /// <summary>Scope requested in the first step.</summary>
    public string Scope { get; }

    internal string CodeVerifier { get; }

    internal string CodeChallenge => Pkce.ComputeChallenge(CodeVerifier);
}

/// <summary>Everything needed to complete a browser (authorization code) login.</summary>
public sealed class AuthorizationRequest
{
    internal AuthorizationRequest(Uri url, string redirectUri, string state, string nonce, string codeVerifier, string scope)
    {
        Url = url;
        RedirectUri = redirectUri;
        State = state;
        Nonce = nonce;
        CodeVerifier = codeVerifier;
        Scope = scope;
    }

    /// <summary>Authorization URL to open in the system browser.</summary>
    public Uri Url { get; }
    public string RedirectUri { get; }
    public string State { get; }
    public string Nonce { get; }
    public string Scope { get; }
    internal string CodeVerifier { get; }
}

/// <summary>Optional parameters of the authorization request.</summary>
public sealed record AuthorizationOptions
{
    public string? Scope { get; init; }
    /// <summary><c>none</c>, <c>login</c>, <c>consent</c> or <c>select_account</c>.</summary>
    public string? Prompt { get; init; }
    public string? LoginHint { get; init; }
    public int? MaxAge { get; init; }
    public string? IdTokenHint { get; init; }
    public string? Resource { get; init; }
    /// <summary>Additional query parameters.</summary>
    public IReadOnlyDictionary<string, string>? ExtraParameters { get; init; }
}

public sealed class ProfileChangedEventArgs : EventArgs
{
    public ProfileChangedEventArgs(UserProfile profile, string source)
    {
        Profile = profile;
        Source = source;
    }

    public UserProfile Profile { get; }

    /// <summary>What triggered the change: <c>login</c>, <c>api</c>, <c>event</c> or <c>resync</c>.</summary>
    public string Source { get; }
}

public sealed class SessionExpiredEventArgs : EventArgs
{
    public SessionExpiredEventArgs(string reason)
    {
        Reason = reason;
    }

    /// <summary>Server description of why the refresh token was rejected (no secrets).</summary>
    public string Reason { get; }
}

public sealed class TokensChangedEventArgs : EventArgs
{
    public TokensChangedEventArgs(TokenSet? tokens)
    {
        Tokens = tokens;
    }

    /// <summary>New tokens, or null after sign-out / session expiry.</summary>
    public TokenSet? Tokens { get; }
}

public sealed class ProfileEventArgs : EventArgs
{
    public ProfileEventArgs(ProfileEvent evt)
    {
        Event = evt;
    }

    public ProfileEvent Event { get; }
}

public sealed class EventStreamErrorEventArgs : EventArgs
{
    public EventStreamErrorEventArgs(Exception error, TimeSpan? retryIn)
    {
        Error = error;
        RetryIn = retryIn;
    }

    public Exception Error { get; }

    /// <summary>Delay before the next connection attempt, or null when the stream stopped for good.</summary>
    public TimeSpan? RetryIn { get; }
}
