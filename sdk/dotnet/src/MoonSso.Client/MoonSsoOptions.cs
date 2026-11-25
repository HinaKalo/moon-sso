namespace MoonSso;

/// <summary>Configuration of a <see cref="MoonSsoClient"/>.</summary>
public sealed class MoonSsoOptions
{
    /// <summary>Production issuer.</summary>
    public const string ProductionIssuer = "https://sso.moonl.cloud";

    /// <summary>Issuer URL. Every other endpoint is discovered from <c>/.well-known/openid-configuration</c>.</summary>
    public string Issuer { get; set; } = ProductionIssuer;

    /// <summary>OAuth client_id.</summary>
    public string ClientId { get; set; } = "";

    /// <summary>Client secret for confidential clients (server-side apps). Leave null for desktop/mobile apps.</summary>
    public string? ClientSecret { get; set; }

    /// <summary>Default scope. Add <c>profile:write</c> / <c>password:write</c> to use the account API.</summary>
    public string Scope { get; set; } = "openid profile offline_access";

    /// <summary>Use DPoP for token requests. Null (default) enables it for public clients, as the SDK spec requires.</summary>
    public bool? UseDPoP { get; set; }

    /// <summary>Where the session is persisted. Defaults to memory only; desktop apps use MoonSso.Desktop's secure stores.</summary>
    public ITokenStore? TokenStore { get; set; }

    /// <summary>Cross-process lock around refresh and store writes. Defaults to none (single process).</summary>
    public IRefreshLock? RefreshLock { get; set; }

    /// <summary>Optional inner HTTP handler (proxies, custom certificates, tests). Not disposed by the SDK.</summary>
    public HttpMessageHandler? HttpHandler { get; set; }

    /// <summary>Timeout of a single OAuth / API HTTP attempt.</summary>
    public TimeSpan HttpTimeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>Fraction of the access token lifetime after which it is refreshed proactively (default 0.75).</summary>
    public double RefreshThreshold { get; set; } = 0.75;

    /// <summary>Refresh in the background when the threshold is reached (in addition to the check before every call).</summary>
    public bool AutoRefresh { get; set; } = true;

    /// <summary>Allowed clock skew for token validation (default 60 s).</summary>
    public TimeSpan ClockSkew { get; set; } = TimeSpan.FromSeconds(60);

    /// <summary>Clock (overridable for tests).</summary>
    public TimeProvider TimeProvider { get; set; } = TimeProvider.System;

    /// <summary>
    /// When set, SDK events (<see cref="MoonSsoClient.ProfileChanged"/>, <see cref="MoonSsoClient.SessionExpired"/>, ...) are posted to this
    /// context, e.g. <c>SynchronizationContext.Current</c> captured on the WPF/WinForms/Avalonia UI thread. Otherwise they are raised on a pool thread.
    /// </summary>
    public SynchronizationContext? EventContext { get; set; }

    /// <summary>Diagnostic log sink. The SDK never logs tokens, passwords or codes.</summary>
    public Action<MoonSsoLogLevel, string>? Logger { get; set; }

    internal bool DPoPEnabled => UseDPoP ?? string.IsNullOrEmpty(ClientSecret);

    internal void Validate()
    {
        if (string.IsNullOrWhiteSpace(ClientId))
        {
            throw new ArgumentException("ClientId is required.", nameof(ClientId));
        }
        DiscoveryCache.NormalizeIssuer(Issuer);
        if (RefreshThreshold is <= 0 or >= 1)
        {
            throw new ArgumentOutOfRangeException(nameof(RefreshThreshold), "Must be between 0 and 1.");
        }
        if (HttpTimeout <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(HttpTimeout));
        }
    }
}

public enum MoonSsoLogLevel
{
    Debug,
    Information,
    Warning,
    Error,
}
