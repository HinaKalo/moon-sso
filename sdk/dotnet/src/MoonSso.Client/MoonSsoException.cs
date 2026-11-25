using System.Net;

namespace MoonSso;

/// <summary>
/// Error raised by the Moon SSO SDK. <see cref="Error"/> is the OAuth error code returned by the
/// server, or <c>network</c> / <c>invalid_response</c> for transport and protocol failures.
/// Messages never contain tokens, passwords or other secrets.
/// </summary>
public class MoonSsoException : Exception
{
    public MoonSsoException(string error, string? errorDescription = null, int? statusCode = null, string? field = null, Exception? innerException = null)
        : base(BuildMessage(error, errorDescription, statusCode), innerException)
    {
        Error = error;
        ErrorDescription = errorDescription;
        StatusCode = statusCode;
        Field = field;
    }

    /// <summary>OAuth error code (<c>invalid_grant</c>, <c>access_denied</c>, ...), or <c>network</c>, <c>invalid_response</c>.</summary>
    public string Error { get; }

    /// <summary>Human readable description from the server (may be Chinese).</summary>
    public string? ErrorDescription { get; }

    /// <summary>HTTP status code, when a response was received.</summary>
    public int? StatusCode { get; }

    /// <summary>Name of the invalid field for 422 validation errors.</summary>
    public string? Field { get; }

    /// <summary>True for failures that may succeed when retried later (network, 5xx, 429). They never end the session.</summary>
    public bool IsTransient =>
        Error is ErrorCodes.Network or "temporarily_unavailable" or "slow_down" or "server_error"
        || StatusCode is >= 500 or (int)HttpStatusCode.TooManyRequests or (int)HttpStatusCode.RequestTimeout;

    private static string BuildMessage(string error, string? description, int? status)
    {
        var msg = error;
        if (!string.IsNullOrEmpty(description))
        {
            msg += ": " + description;
        }
        if (status is not null)
        {
            msg += $" (HTTP {status})";
        }
        return msg;
    }
}

/// <summary>
/// The refresh token was rejected with <c>invalid_grant</c>: the session is over (signed out elsewhere,
/// password changed on another device, consent revoked, account disabled...). The user must sign in again.
/// </summary>
public sealed class SessionExpiredException : MoonSsoException
{
    public SessionExpiredException(string? description = null, int? statusCode = null, Exception? inner = null)
        : base(ErrorCodes.InvalidGrant, description, statusCode, null, inner)
    {
    }
}

/// <summary>No session is available (never signed in, or signed out).</summary>
public sealed class NotSignedInException : MoonSsoException
{
    public NotSignedInException()
        : base(ErrorCodes.LoginRequired, "No Moon SSO session; sign in first.")
    {
    }
}

/// <summary>
/// First-party login needs a second factor. Show an OTP input and call
/// <see cref="MoonSsoClient.SubmitOtpAsync(OtpChallenge, string, CancellationToken)"/> with <see cref="Challenge"/>.
/// </summary>
public sealed class OtpRequiredException : MoonSsoException
{
    public OtpRequiredException(OtpChallenge challenge, string? description, int? statusCode)
        : base(ErrorCodes.InsufficientAuthorization, description, statusCode)
    {
        Challenge = challenge;
    }

    /// <summary>The pending challenge (auth session + the PKCE verifier kept by the SDK).</summary>
    public OtpChallenge Challenge { get; }

    /// <summary>The opaque <c>auth_session</c> issued by the server.</summary>
    public string AuthSession => Challenge.AuthSession;
}

/// <summary>An administrator reset the password; the user must set a new one in the browser at <see cref="ChangeUrl"/>.</summary>
public sealed class PasswordChangeRequiredException : MoonSsoException
{
    public PasswordChangeRequiredException(string? changeUrl, string? description, int? statusCode)
        : base(ErrorCodes.PasswordChangeRequired, description, statusCode)
    {
        ChangeUrl = changeUrl is null ? null : new Uri(changeUrl, UriKind.Absolute);
    }

    public Uri? ChangeUrl { get; }
}

/// <summary>Well-known error codes.</summary>
public static class ErrorCodes
{
    public const string Network = "network";
    public const string InvalidResponse = "invalid_response";
    public const string InvalidGrant = "invalid_grant";
    public const string InvalidClient = "invalid_client";
    public const string UseDPoPNonce = "use_dpop_nonce";
    public const string InvalidDPoPProof = "invalid_dpop_proof";
    public const string InsufficientAuthorization = "insufficient_authorization";
    public const string PasswordChangeRequired = "password_change_required";
    public const string LoginRequired = "login_required";
    public const string RegistrationClosed = "registration_closed";
    public const string AccessDenied = "access_denied";
    public const string InvalidState = "invalid_state";
    public const string InvalidIssuer = "invalid_issuer";
    public const string InvalidIdToken = "invalid_id_token";
    public const string VersionConflict = "version_conflict";
    public const string LockTimeout = "lock_timeout";
}
