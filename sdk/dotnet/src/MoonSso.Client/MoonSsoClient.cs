using System.Net;
using System.Net.Http.Headers;
using System.Reflection;
using System.Text;
using System.Text.Json;
using MoonSso.Internal;

namespace MoonSso;

/// <summary>
/// Moon SSO client for desktop, mobile and server applications: login (first-party challenge with OTP, browser code flow, native
/// registration), silent token renewal, the account API, and live profile events.
/// </summary>
/// <remarks>Create one instance per application (it is thread-safe) and dispose it on exit.</remarks>
public sealed class MoonSsoClient : IAsyncDisposable, IDisposable
{
    private const long MaxAvatarBytes = 5 * 1024 * 1024;

    private readonly MoonSsoOptions _options;
    private readonly HttpMessageHandler _baseHandler;
    private readonly bool _ownsHandler;
    private readonly HttpClient _http;
    private readonly HttpClient _apiHttp;
    private readonly OAuthTransport _transport;
    private readonly Logger _log;
    private readonly EventDispatcher _events;
    private readonly object _streamSync = new();
    private MoonSsoEventStream? _stream;
    private OtpChallenge? _pendingOtp;
    private int _disposed;

    /// <summary>The SDK User-Agent (<c>moon-sso-sdk-dotnet/&lt;version&gt;</c>).</summary>
    public static readonly string UserAgent = "moon-sso-sdk-dotnet/" + SdkVersion;

    public MoonSsoClient(MoonSsoOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();
        _options = options;
        _log = new Logger(options.Logger);
        _events = new EventDispatcher(options.EventContext, _log);
        if (options.HttpHandler is not null)
        {
            _baseHandler = options.HttpHandler;
        }
        else
        {
            _baseHandler = new SocketsHttpHandler
            {
                PooledConnectionLifetime = TimeSpan.FromMinutes(5),
                AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate,
                AllowAutoRedirect = false,
                UseCookies = false,
            };
            _ownsHandler = true;
        }
        _http = CreateRawHttpClient(_baseHandler);
        Discovery = new DiscoveryCache(_http, options.Issuer, options.TimeProvider);
        Jwks = new JwksCache(_http, Discovery, options.TimeProvider);
        Validator = new TokenValidator(Jwks, options.Issuer, options.TimeProvider, options.ClockSkew);
        _transport = new OAuthTransport(_http, options, new DPoPNonceCache(), _log);
        Tokens = new TokenManager(options, options.TokenStore ?? new InMemoryTokenStore(), options.RefreshLock ?? NoRefreshLock.Instance, RefreshTokensAsync, _log, _events);
        Tokens.ProfileFromTokens += p => _events.Raise(() => ProfileChanged?.Invoke(this, new ProfileChangedEventArgs(p, "token")));
        _apiHttp = new HttpClient(new MoonSsoAuthHandler(Tokens) { InnerHandler = _baseHandler }, disposeHandler: false) { Timeout = Timeout.InfiniteTimeSpan };
        _apiHttp.DefaultRequestHeaders.UserAgent.ParseAdd(UserAgent);
    }

    internal static string SdkVersion
    {
        get
        {
            var v = typeof(MoonSsoClient).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "1.0.0";
            var plus = v.IndexOf('+');
            return plus >= 0 ? v[..plus] : v;
        }
    }

    public MoonSsoOptions Options => _options;

    /// <summary>Token lifecycle (refresh, persistence, cross-process coordination).</summary>
    public TokenManager Tokens { get; }

    public DiscoveryCache Discovery { get; }

    public JwksCache Jwks { get; }

    /// <summary>ID / access token validator bound to this issuer.</summary>
    public TokenValidator Validator { get; }

    /// <summary>True when tokens are available (call <see cref="InitializeAsync"/> first to load a persisted session).</summary>
    public bool IsSignedIn => Tokens.IsSignedIn;

    /// <summary>Cached profile (from the ID token, the account API or events).</summary>
    public UserProfile? CurrentProfile => Tokens.Profile;

    /// <summary>The profile changed (login, account API call, live event or newer ID token).</summary>
    public event EventHandler<ProfileChangedEventArgs>? ProfileChanged;

    /// <summary>The session ended and the user must sign in again (only after <c>invalid_grant</c>; never for network errors).</summary>
    public event EventHandler<SessionExpiredEventArgs>? SessionExpired
    {
        add => Tokens.SessionExpired += value;
        remove => Tokens.SessionExpired -= value;
    }

    /// <summary>Tokens were obtained, refreshed or removed.</summary>
    public event EventHandler<TokensChangedEventArgs>? TokensChanged
    {
        add => Tokens.TokensChanged += value;
        remove => Tokens.TokensChanged -= value;
    }

    /// <summary>Loads the persisted session. Returns true when the user is signed in.</summary>
    public Task<bool> InitializeAsync(CancellationToken cancellationToken = default) => Tokens.LoadAsync(cancellationToken);

    public Task<DiscoveryDocument> GetDiscoveryAsync(CancellationToken cancellationToken = default) => Discovery.GetAsync(cancellationToken);

    /// <summary>Returns a valid access token (refreshing when needed).</summary>
    public Task<string> GetAccessTokenAsync(CancellationToken cancellationToken = default) => Tokens.GetAccessTokenAsync(cancellationToken);

    /// <summary>Refreshes the tokens now.</summary>
    public Task<TokenSet> RefreshAsync(CancellationToken cancellationToken = default) => Tokens.RefreshAsync(cancellationToken);

    // ------------------------------------------------------------------ first-party login

    /// <summary>
    /// In-app login with username and password (<c>/oauth/authorize-challenge</c>; the client must be first-party with native login).
    /// </summary>
    /// <exception cref="OtpRequiredException">A second factor is needed: call <see cref="SubmitOtpAsync(OtpChallenge, string, CancellationToken)"/>.</exception>
    /// <exception cref="PasswordChangeRequiredException">The user must change the password in the browser first.</exception>
    /// <exception cref="MoonSsoException"><c>access_denied</c> for wrong credentials, <c>slow_down</c> when throttled, ...</exception>
    public async Task<TokenSet> LoginWithPasswordAsync(string username, string password, string? scope = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(username);
        ArgumentException.ThrowIfNullOrEmpty(password);
        var pkce = Pkce.Create();
        scope ??= _options.Scope;
        var form = new List<KeyValuePair<string, string>>
        {
            new("username", username),
            new("password", password),
            new("scope", scope),
            new("code_challenge", pkce.CodeChallenge),
            new("code_challenge_method", "S256"),
        };
        return await ChallengeAsync(form, pkce.CodeVerifier, scope, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Second step of a first-party login: submits the one-time code for <paramref name="challenge"/>.</summary>
    /// <exception cref="OtpRequiredException">The code was wrong; ask again (same challenge).</exception>
    /// <exception cref="MoonSsoException"><c>invalid_grant</c> when the auth session expired (5 minutes): start over.</exception>
    public async Task<TokenSet> SubmitOtpAsync(OtpChallenge challenge, string otp, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(challenge);
        ArgumentException.ThrowIfNullOrEmpty(otp);
        var form = new List<KeyValuePair<string, string>>
        {
            new("auth_session", challenge.AuthSession),
            new("otp", otp.Trim()),
            new("scope", challenge.Scope),
            new("code_challenge", challenge.CodeChallenge),
            new("code_challenge_method", "S256"),
        };
        return await ChallengeAsync(form, challenge.CodeVerifier, challenge.Scope, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Submits the one-time code for the most recent <see cref="OtpRequiredException"/> of this client.</summary>
    public Task<TokenSet> SubmitOtpAsync(string otp, CancellationToken cancellationToken = default)
    {
        var pending = Volatile.Read(ref _pendingOtp) ?? throw new InvalidOperationException("No OTP challenge is pending.");
        return SubmitOtpAsync(pending, otp, cancellationToken);
    }

    private async Task<TokenSet> ChallengeAsync(List<KeyValuePair<string, string>> form, string verifier, string scope, CancellationToken ct)
    {
        var doc = await Discovery.GetAsync(ct).ConfigureAwait(false);
        var endpoint = doc.AuthorizationChallengeEndpoint ?? Discovery.Issuer + "/oauth/authorize-challenge";
        var key = _options.DPoPEnabled ? await Tokens.GetOrCreateDPoPKeyAsync(ct).ConfigureAwait(false) : null;
        var resp = await _transport.PostFormAsync(endpoint, form, key, retryTransient: false, htu: null, ct).ConfigureAwait(false);
        return await CompleteDirectCodeAsync(resp, verifier, scope, key, endpoint, ct).ConfigureAwait(false);
    }

    private async Task<TokenSet> CompleteDirectCodeAsync(OAuthResponse resp, string verifier, string scope, DPoPKey? key, string endpoint, CancellationToken ct)
    {
        if (!resp.IsSuccess)
        {
            switch (resp.Error)
            {
                case ErrorCodes.InsufficientAuthorization when resp.Body.GetString("auth_session") is { } authSession:
                    var challenge = new OtpChallenge(authSession, verifier, scope);
                    Volatile.Write(ref _pendingOtp, challenge);
                    throw new OtpRequiredException(challenge, resp.Body.GetString("error_description"), resp.Status);
                case ErrorCodes.PasswordChangeRequired:
                    throw new PasswordChangeRequiredException(resp.Body.GetString("change_url"), resp.Body.GetString("error_description"), resp.Status);
                case ErrorCodes.AccessDenied when endpoint.EndsWith("/native/register", StringComparison.Ordinal) && resp.Status == 403:
                    throw new MoonSsoException(ErrorCodes.RegistrationClosed, resp.Body.GetString("error_description"), resp.Status);
                default:
                    throw resp.ToException();
            }
        }
        var code = resp.Body.GetString("authorization_code") ?? throw new MoonSsoException(ErrorCodes.InvalidResponse, "No authorization_code in response.", resp.Status);
        Volatile.Write(ref _pendingOtp, null);
        return await ExchangeAndStoreAsync(code, verifier, redirectUri: null, nonce: null, key, ct).ConfigureAwait(false);
    }

    // ------------------------------------------------------------------ registration

    /// <summary>
    /// Creates an account inside a first-party app (<c>/api/v1/native/register</c>) and signs the new user in.
    /// </summary>
    /// <exception cref="MoonSsoException">422 with <see cref="MoonSsoException.Field"/> for invalid input; <c>registration_closed</c> (403).</exception>
    public async Task<TokenSet> RegisterAsync(NativeRegistration registration, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentException.ThrowIfNullOrEmpty(registration.Username);
        ArgumentException.ThrowIfNullOrEmpty(registration.Password);
        var pkce = Pkce.Create();
        var scope = registration.Scope ?? _options.Scope;
        var form = new List<KeyValuePair<string, string>>
        {
            new("username", registration.Username),
            new("password", registration.Password),
            new("display_name", registration.DisplayName ?? ""),
            new("scope", scope),
            new("code_challenge", pkce.CodeChallenge),
            new("code_challenge_method", "S256"),
        };
        var endpoint = Discovery.Issuer + "/api/v1/native/register";
        var key = _options.DPoPEnabled ? await Tokens.GetOrCreateDPoPKeyAsync(cancellationToken).ConfigureAwait(false) : null;
        var resp = await _transport.PostFormAsync(endpoint, form, key, retryTransient: false, htu: null, cancellationToken).ConfigureAwait(false);
        if (key is not null && !resp.IsSuccess && resp.Error == ErrorCodes.InvalidDPoPProof)
        {
            // Compatibility: some server versions verify the proof of this endpoint against the authorize-challenge URL.
            var doc = await Discovery.GetAsync(cancellationToken).ConfigureAwait(false);
            var challengeHtu = doc.AuthorizationChallengeEndpoint ?? Discovery.Issuer + "/oauth/authorize-challenge";
            _log.Debug("native/register rejected the DPoP htu; retrying with the authorize-challenge htu.");
            resp = await _transport.PostFormAsync(endpoint, form, key, retryTransient: false, htu: challengeHtu, cancellationToken).ConfigureAwait(false);
        }
        return await CompleteDirectCodeAsync(resp, pkce.CodeVerifier, scope, key, endpoint, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Whether self-service registration is open, plus password and username rules.</summary>
    public async Task<RegistrationInfo> GetRegistrationInfoAsync(CancellationToken cancellationToken = default)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, Discovery.Issuer + "/api/v1/registration");
        var body = await SendRawJsonAsync(req, cancellationToken).ConfigureAwait(false);
        return Json.Deserialize<RegistrationInfo>(body);
    }

    // ------------------------------------------------------------------ browser (authorization code) flow

    /// <summary>
    /// Builds an authorization request (PKCE S256, state, nonce and <c>dpop_jkt</c>) for <paramref name="redirectUri"/>.
    /// Open <see cref="AuthorizationRequest.Url"/> in the system browser, then call <see cref="ExchangeCodeAsync(AuthorizationRequest, Uri, CancellationToken)"/>.
    /// </summary>
    public async Task<AuthorizationRequest> CreateAuthorizationRequestAsync(string redirectUri, AuthorizationOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(redirectUri);
        options ??= new AuthorizationOptions();
        var doc = await Discovery.GetAsync(cancellationToken).ConfigureAwait(false);
        var pkce = Pkce.Create();
        var state = Pkce.RandomValue();
        var nonce = Pkce.RandomValue();
        var scope = options.Scope ?? _options.Scope;
        var q = new List<KeyValuePair<string, string>>
        {
            new("response_type", "code"),
            new("client_id", _options.ClientId),
            new("redirect_uri", redirectUri),
            new("scope", scope),
            new("state", state),
            new("nonce", nonce),
            new("code_challenge", pkce.CodeChallenge),
            new("code_challenge_method", "S256"),
        };
        if (options.Prompt is not null) q.Add(new("prompt", options.Prompt));
        if (options.LoginHint is not null) q.Add(new("login_hint", options.LoginHint));
        if (options.MaxAge is not null) q.Add(new("max_age", options.MaxAge.Value.ToString(System.Globalization.CultureInfo.InvariantCulture)));
        if (options.IdTokenHint is not null) q.Add(new("id_token_hint", options.IdTokenHint));
        if (options.Resource is not null) q.Add(new("resource", options.Resource));
        if (_options.DPoPEnabled)
        {
            var key = await Tokens.GetOrCreateDPoPKeyAsync(cancellationToken).ConfigureAwait(false);
            q.Add(new("dpop_jkt", key.Thumbprint));
        }
        if (options.ExtraParameters is not null)
        {
            foreach (var kv in options.ExtraParameters)
            {
                q.Add(kv);
            }
        }
        var url = new Uri(doc.AuthorizationEndpoint + (doc.AuthorizationEndpoint.Contains('?') ? "&" : "?") + QueryString.Build(q));
        return new AuthorizationRequest(url, redirectUri, state, nonce, pkce.CodeVerifier, scope);
    }

    /// <summary>
    /// Completes a browser login from the callback URL: checks <c>error</c>, <c>state</c> and <c>iss</c> (RFC 9207), redeems the code
    /// and validates the ID token (including the nonce).
    /// </summary>
    public Task<TokenSet> ExchangeCodeAsync(AuthorizationRequest request, Uri callbackUri, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(callbackUri);
        return ExchangeCodeAsync(request, QueryString.Parse(callbackUri.Query), cancellationToken);
    }

    /// <summary>Completes a browser login from the callback parameters (query or form_post fields).</summary>
    public async Task<TokenSet> ExchangeCodeAsync(AuthorizationRequest request, IReadOnlyDictionary<string, string> callbackParameters, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(callbackParameters);
        var doc = await Discovery.GetAsync(cancellationToken).ConfigureAwait(false);
        callbackParameters.TryGetValue("state", out var state);
        if (!TokenValidator.FixedEquals(state, request.State))
        {
            throw new MoonSsoException(ErrorCodes.InvalidState, "The state parameter of the callback does not match the request.");
        }
        if (callbackParameters.TryGetValue("iss", out var iss))
        {
            if (iss.TrimEnd('/') != Discovery.Issuer)
            {
                throw new MoonSsoException(ErrorCodes.InvalidIssuer, "The iss parameter of the callback does not match the issuer.");
            }
        }
        else if (doc.AuthorizationResponseIssParameterSupported)
        {
            throw new MoonSsoException(ErrorCodes.InvalidIssuer, "The callback has no iss parameter.");
        }
        if (callbackParameters.TryGetValue("error", out var error))
        {
            callbackParameters.TryGetValue("error_description", out var description);
            throw new MoonSsoException(error, description);
        }
        if (!callbackParameters.TryGetValue("code", out var code) || string.IsNullOrEmpty(code))
        {
            throw new MoonSsoException(ErrorCodes.InvalidResponse, "The callback has no authorization code.");
        }
        var key = _options.DPoPEnabled ? await Tokens.GetOrCreateDPoPKeyAsync(cancellationToken).ConfigureAwait(false) : null;
        return await ExchangeAndStoreAsync(code, request.CodeVerifier, request.RedirectUri, request.Nonce, key, cancellationToken).ConfigureAwait(false);
    }

    private async Task<TokenSet> ExchangeAndStoreAsync(string code, string verifier, string? redirectUri, string? nonce, DPoPKey? key, CancellationToken ct)
    {
        var doc = await Discovery.GetAsync(ct).ConfigureAwait(false);
        var form = new List<KeyValuePair<string, string>>
        {
            new("grant_type", "authorization_code"),
            new("code", code),
            new("code_verifier", verifier),
        };
        if (redirectUri is not null)
        {
            form.Add(new("redirect_uri", redirectUri));
        }
        // No transient retry here: replaying a redeemed code makes the server revoke the tokens it produced.
        var resp = await _transport.PostFormAsync(doc.TokenEndpoint, form, key, retryTransient: false, htu: null, ct).ConfigureAwait(false);
        if (!resp.IsSuccess)
        {
            throw resp.ToException();
        }
        var (tokens, profile) = await ParseTokenResponseAsync(resp, nonce, expectedSub: null, ct).ConfigureAwait(false);
        await Tokens.SetSessionAsync(tokens, profile, key, ct).ConfigureAwait(false);
        if (profile is not null)
        {
            _events.Raise(() => ProfileChanged?.Invoke(this, new ProfileChangedEventArgs(profile, "login")));
        }
        _log.Info("Signed in.");
        return tokens;
    }

    private async Task<(TokenSet, UserProfile?)> RefreshTokensAsync(TokenSet current, DPoPKey? key, CancellationToken ct)
    {
        var doc = await Discovery.GetAsync(ct).ConfigureAwait(false);
        var form = new List<KeyValuePair<string, string>>
        {
            new("grant_type", "refresh_token"),
            new("refresh_token", current.RefreshToken!),
        };
        var resp = await _transport.PostFormAsync(doc.TokenEndpoint, form, key, retryTransient: true, htu: null, ct).ConfigureAwait(false);
        if (!resp.IsSuccess)
        {
            if (resp.Error == ErrorCodes.InvalidGrant)
            {
                throw new SessionExpiredException(resp.Body.GetString("error_description"), resp.Status);
            }
            throw resp.ToException();
        }
        return await ParseTokenResponseAsync(resp, expectedNonce: null, expectedSub: Tokens.Profile?.Sub, ct).ConfigureAwait(false);
    }

    private async Task<(TokenSet, UserProfile?)> ParseTokenResponseAsync(OAuthResponse resp, string? expectedNonce, string? expectedSub, CancellationToken ct)
    {
        var body = resp.Body;
        var accessToken = body.GetString("access_token");
        if (string.IsNullOrEmpty(accessToken))
        {
            throw new MoonSsoException(ErrorCodes.InvalidResponse, "Token response has no access_token.", resp.Status);
        }
        var expiresIn = body.GetInt64("expires_in") ?? 300;
        if (expiresIn <= 0)
        {
            expiresIn = 60;
        }
        var idToken = body.GetString("id_token");
        UserProfile? profile = null;
        if (idToken is not null)
        {
            var claims = await Validator.ValidateIdTokenAsync(idToken, _options.ClientId, expectedNonce, accessToken, ct).ConfigureAwait(false);
            if (expectedSub is not null && claims.Subject != expectedSub)
            {
                throw new MoonSsoException(ErrorCodes.InvalidIdToken, "Refreshed ID token belongs to a different subject.");
            }
            profile = claims.ToProfile();
        }
        var now = _options.TimeProvider.GetUtcNow();
        var tokens = new TokenSet
        {
            AccessToken = accessToken,
            TokenType = body.GetString("token_type") ?? "Bearer",
            RefreshToken = body.GetString("refresh_token"),
            IdToken = idToken,
            Scope = body.GetString("scope"),
            IssuedAt = now,
            ExpiresAt = now.AddSeconds(expiresIn),
        };
        return (tokens, profile);
    }

    // ------------------------------------------------------------------ logout

    /// <summary>
    /// Signs out locally (tokens removed from the store) and revokes the refresh and access tokens at the server.
    /// Revocation failures never prevent the local sign-out.
    /// </summary>
    public async Task LogoutAsync(CancellationToken cancellationToken = default)
    {
        await StopEventsAsync().ConfigureAwait(false);
        var old = await Tokens.ClearAsync(cancellationToken).ConfigureAwait(false);
        Volatile.Write(ref _pendingOtp, null);
        if (old is null)
        {
            return;
        }
        try
        {
            var doc = await Discovery.GetAsync(cancellationToken).ConfigureAwait(false);
            var endpoint = doc.RevocationEndpoint ?? Discovery.Issuer + "/oauth/revoke";
            if (old.RefreshToken is not null)
            {
                await _transport.PostFormAsync(endpoint, new List<KeyValuePair<string, string>> { new("token", old.RefreshToken), new("token_type_hint", "refresh_token") },
                    null, retryTransient: false, htu: null, cancellationToken).ConfigureAwait(false);
            }
            await _transport.PostFormAsync(endpoint, new List<KeyValuePair<string, string>> { new("token", old.AccessToken), new("token_type_hint", "access_token") },
                null, retryTransient: false, htu: null, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is MoonSsoException or HttpRequestException)
        {
            _log.Warning($"Token revocation failed ({(ex as MoonSsoException)?.Error ?? ex.GetType().Name}); signed out locally.");
        }
    }

    /// <summary>
    /// RP-initiated logout URL (<c>end_session_endpoint</c>) for browser sign-out. Call before <see cref="LogoutAsync"/> so the ID token hint is available.
    /// </summary>
    public async Task<Uri> GetEndSessionUrlAsync(string? postLogoutRedirectUri = null, string? state = null, string? idTokenHint = null, CancellationToken cancellationToken = default)
    {
        var doc = await Discovery.GetAsync(cancellationToken).ConfigureAwait(false);
        var endpoint = doc.EndSessionEndpoint ?? Discovery.Issuer + "/oauth/end_session";
        var q = new List<KeyValuePair<string, string>> { new("client_id", _options.ClientId) };
        idTokenHint ??= Tokens.Current?.IdToken;
        if (idTokenHint is not null) q.Add(new("id_token_hint", idTokenHint));
        if (postLogoutRedirectUri is not null) q.Add(new("post_logout_redirect_uri", postLogoutRedirectUri));
        if (state is not null) q.Add(new("state", state));
        return new Uri(endpoint + (endpoint.Contains('?') ? "&" : "?") + QueryString.Build(q));
    }

    // ------------------------------------------------------------------ account API

    /// <summary><c>GET /api/v1/me</c>. Uses the cached ETag; updates the cached profile and raises <see cref="ProfileChanged"/> when it changed.</summary>
    public async Task<UserProfile> GetMeAsync(CancellationToken cancellationToken = default)
        => await GetMeCoreAsync("api", cancellationToken).ConfigureAwait(false);

    internal async Task<UserProfile> GetMeCoreAsync(string source, CancellationToken ct)
    {
        await Tokens.LoadAsync(ct).ConfigureAwait(false);
        var doc = await Discovery.GetAsync(ct).ConfigureAwait(false);
        using var req = new HttpRequestMessage(HttpMethod.Get, doc.ApiBase + "/me");
        var cached = Tokens.Profile;
        if (cached is not null && Tokens.ProfileETag is { } etag && cached.TotpEnabled is not null)
        {
            req.Headers.TryAddWithoutValidation("If-None-Match", etag);
        }
        using var resp = await SendApiAsync(req, ct).ConfigureAwait(false);
        if (resp.StatusCode == HttpStatusCode.NotModified && cached is not null)
        {
            return cached;
        }
        var body = await EnsureApiSuccessAsync(resp, ct).ConfigureAwait(false);
        var profile = Json.Deserialize<UserProfile>(body);
        await ApplyProfileAsync(profile, resp.Headers.ETag?.ToString(), source, ct).ConfigureAwait(false);
        return profile;
    }

    /// <summary><c>PATCH /api/v1/me</c> (scope <c>profile:write</c>): change username and/or display name.</summary>
    /// <exception cref="MoonSsoException">422 with <see cref="MoonSsoException.Field"/>; 412 <c>version_conflict</c> with <see cref="ProfileUpdate.IfMatchVersion"/>.</exception>
    public async Task<UserProfile> UpdateProfileAsync(ProfileUpdate update, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(update);
        var doc = await Discovery.GetAsync(cancellationToken).ConfigureAwait(false);
        using var req = new HttpRequestMessage(HttpMethod.Patch, doc.ApiBase + "/me")
        {
            Content = new ByteArrayContent(JsonSerializer.SerializeToUtf8Bytes(update, Json.Options)),
        };
        req.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json") { CharSet = "utf-8" };
        if (update.IfMatchVersion is { } v)
        {
            req.Headers.TryAddWithoutValidation("If-Match", $"\"pv-{v}\"");
        }
        return await SendProfileMutationAsync(req, cancellationToken).ConfigureAwait(false);
    }

    /// <summary><c>PUT /api/v1/me/avatar</c> (scope <c>profile:write</c>) with the raw image bytes (max 5 MB).</summary>
    /// <param name="image">Image bytes (PNG, JPEG, WebP or GIF).</param>
    /// <param name="contentType">For example <c>image/png</c>.</param>
    public async Task<UserProfile> UploadAvatarAsync(byte[] image, string contentType, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(image);
        if (image.Length > MaxAvatarBytes)
        {
            throw new ArgumentException("Avatar images are limited to 5 MB.", nameof(image));
        }
        return await UploadAvatarCoreAsync(new ByteArrayContent(image), contentType, cancellationToken).ConfigureAwait(false);
    }

    /// <summary><c>PUT /api/v1/me/avatar</c> from a stream (max 5 MB; the stream is buffered so the request can be replayed after a token refresh).</summary>
    public async Task<UserProfile> UploadAvatarAsync(Stream image, string contentType, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(image);
        using var ms = new MemoryStream();
        var buffer = new byte[81920];
        int read;
        while ((read = await image.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) > 0)
        {
            if (ms.Length + read > MaxAvatarBytes)
            {
                throw new ArgumentException("Avatar images are limited to 5 MB.", nameof(image));
            }
            ms.Write(buffer, 0, read);
        }
        return await UploadAvatarCoreAsync(new ByteArrayContent(ms.ToArray()), contentType, cancellationToken).ConfigureAwait(false);
    }

    private async Task<UserProfile> UploadAvatarCoreAsync(ByteArrayContent content, string contentType, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrEmpty(contentType);
        if (!contentType.StartsWith("image/", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("Content type must be an image type.", nameof(contentType));
        }
        var doc = await Discovery.GetAsync(ct).ConfigureAwait(false);
        using var req = new HttpRequestMessage(HttpMethod.Put, doc.ApiBase + "/me/avatar") { Content = content };
        content.Headers.ContentType = new MediaTypeHeaderValue(contentType);
        return await SendProfileMutationAsync(req, ct).ConfigureAwait(false);
    }

    /// <summary><c>DELETE /api/v1/me/avatar</c> (scope <c>profile:write</c>).</summary>
    public async Task<UserProfile> DeleteAvatarAsync(CancellationToken cancellationToken = default)
    {
        var doc = await Discovery.GetAsync(cancellationToken).ConfigureAwait(false);
        using var req = new HttpRequestMessage(HttpMethod.Delete, doc.ApiBase + "/me/avatar");
        return await SendProfileMutationAsync(req, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>POST /api/v1/me/password</c> (scope <c>password:write</c>). Other devices are signed out; this device stays signed in unless
    /// <paramref name="keepThisDevice"/> is false.
    /// </summary>
    public async Task ChangePasswordAsync(string currentPassword, string newPassword, bool keepThisDevice = true, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(currentPassword);
        ArgumentException.ThrowIfNullOrEmpty(newPassword);
        var doc = await Discovery.GetAsync(cancellationToken).ConfigureAwait(false);
        var payload = JsonSerializer.SerializeToUtf8Bytes(new Dictionary<string, object>
        {
            ["current_password"] = currentPassword,
            ["new_password"] = newPassword,
            ["keep_this_device"] = keepThisDevice,
        });
        using var req = new HttpRequestMessage(HttpMethod.Post, doc.ApiBase + "/me/password") { Content = new ByteArrayContent(payload) };
        req.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json") { CharSet = "utf-8" };
        using var resp = await SendApiAsync(req, cancellationToken).ConfigureAwait(false);
        await EnsureApiSuccessAsync(resp, cancellationToken).ConfigureAwait(false);
    }

    private async Task<UserProfile> SendProfileMutationAsync(HttpRequestMessage req, CancellationToken ct)
    {
        using var resp = await SendApiAsync(req, ct).ConfigureAwait(false);
        var body = await EnsureApiSuccessAsync(resp, ct).ConfigureAwait(false);
        var profile = Json.Deserialize<UserProfile>(body);
        await ApplyProfileAsync(profile, resp.Headers.ETag?.ToString(), "api", ct).ConfigureAwait(false);
        return profile;
    }

    /// <summary>Updates the cached profile and raises <see cref="ProfileChanged"/> if anything changed.</summary>
    internal async Task ApplyProfileAsync(UserProfile profile, string? etag, string source, CancellationToken ct)
    {
        var cached = Tokens.Profile;
        if (cached is not null && cached.Sub == profile.Sub && profile.ProfileVersion < cached.ProfileVersion)
        {
            return; // older than what we already have
        }
        if (profile.TotpEnabled is null && cached?.TotpEnabled is { } totp && cached.Sub == profile.Sub)
        {
            profile = profile with { TotpEnabled = totp };
        }
        await Tokens.SetProfileAsync(profile, etag ?? $"\"pv-{profile.ProfileVersion}\"", CancellationToken.None).ConfigureAwait(false);
        if (cached != profile)
        {
            _events.Raise(() => ProfileChanged?.Invoke(this, new ProfileChangedEventArgs(profile, source)));
        }
    }

    internal async Task<HttpResponseMessage> SendApiAsync(HttpRequestMessage req, CancellationToken ct)
    {
        req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(_options.HttpTimeout);
        try
        {
            return await _apiHttp.SendAsync(req, HttpCompletionOption.ResponseContentRead, timeout.Token).ConfigureAwait(false);
        }
        catch (Exception ex) when (OAuthTransport.IsNetworkFailure(ex, ct))
        {
            throw new MoonSsoException(ErrorCodes.Network, $"Request to {req.RequestUri?.AbsolutePath} failed: {ex.Message}", innerException: ex);
        }
    }

    private static async Task<JsonElement> EnsureApiSuccessAsync(HttpResponseMessage resp, CancellationToken ct)
    {
        var body = await OAuthTransport.ReadJsonAsync(resp, ct).ConfigureAwait(false);
        var result = new OAuthResponse((int)resp.StatusCode, body);
        if (!result.IsSuccess)
        {
            if (resp.StatusCode == HttpStatusCode.Unauthorized && result.Error is null)
            {
                throw new MoonSsoException("invalid_token", "The access token was rejected.", 401);
            }
            throw result.ToException();
        }
        return body;
    }

    private async Task<JsonElement> SendRawJsonAsync(HttpRequestMessage req, CancellationToken ct)
    {
        req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(_options.HttpTimeout);
        HttpResponseMessage resp;
        try
        {
            resp = await _http.SendAsync(req, timeout.Token).ConfigureAwait(false);
        }
        catch (Exception ex) when (OAuthTransport.IsNetworkFailure(ex, ct))
        {
            throw new MoonSsoException(ErrorCodes.Network, $"Request to {req.RequestUri?.AbsolutePath} failed: {ex.Message}", innerException: ex);
        }
        using (resp)
        {
            return await EnsureApiSuccessAsync(resp, ct).ConfigureAwait(false);
        }
    }

    // ------------------------------------------------------------------ HTTP integration

    /// <summary>
    /// Creates a handler that adds <c>Authorization: Bearer</c> to requests, refreshes proactively and replays once after a 401.
    /// Set its <see cref="DelegatingHandler.InnerHandler"/> or leave it null to use a new <see cref="SocketsHttpHandler"/>.
    /// </summary>
    public MoonSsoAuthHandler CreateAuthHandler(HttpMessageHandler? innerHandler = null) =>
        new(Tokens) { InnerHandler = innerHandler ?? new SocketsHttpHandler { PooledConnectionLifetime = TimeSpan.FromMinutes(5) } };

    /// <summary>Creates an <see cref="HttpClient"/> that authenticates your own API calls with the user's access token.</summary>
    public HttpClient CreateHttpClient(Uri? baseAddress = null)
    {
        var client = new HttpClient(CreateAuthHandler(), disposeHandler: true);
        if (baseAddress is not null)
        {
            client.BaseAddress = baseAddress;
        }
        return client;
    }

    internal HttpClient RawHttp => _http;

    internal Logger Log => _log;

    internal EventDispatcher Dispatcher => _events;

    internal void RaiseProfileChanged(UserProfile profile, string source) =>
        _events.Raise(() => ProfileChanged?.Invoke(this, new ProfileChangedEventArgs(profile, source)));

    // ------------------------------------------------------------------ live events

    /// <summary>The live profile event stream of this client (SSE). Use <see cref="StartEvents"/> to run it in the background.</summary>
    public MoonSsoEventStream Events
    {
        get
        {
            lock (_streamSync)
            {
                return _stream ??= new MoonSsoEventStream(this, CreateRawHttpClient(_baseHandler));
            }
        }
    }

    /// <summary>
    /// Starts listening to <c>/api/v1/me/events</c> in the background. Profile updates raise <see cref="ProfileChanged"/>;
    /// sign-out elsewhere, password changes on other devices, disabled accounts and revoked consent raise <see cref="SessionExpired"/>.
    /// </summary>
    public void StartEvents() => Events.Start();

    /// <summary>Stops the background event stream.</summary>
    public Task StopEventsAsync()
    {
        MoonSsoEventStream? s;
        lock (_streamSync)
        {
            s = _stream;
        }
        return s?.StopAsync() ?? Task.CompletedTask;
    }

    private static HttpClient CreateRawHttpClient(HttpMessageHandler handler)
    {
        var http = new HttpClient(handler, disposeHandler: false) { Timeout = Timeout.InfiniteTimeSpan };
        http.DefaultRequestHeaders.UserAgent.ParseAdd(UserAgent);
        return http;
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }
        MoonSsoEventStream? s;
        lock (_streamSync)
        {
            s = _stream;
        }
        if (s is not null)
        {
            await s.DisposeAsync().ConfigureAwait(false);
        }
        await Tokens.DisposeAsync().ConfigureAwait(false);
        _apiHttp.Dispose();
        _http.Dispose();
        if (_ownsHandler)
        {
            _baseHandler.Dispose();
        }
    }

    public void Dispose() => DisposeAsync().AsTask().GetAwaiter().GetResult();
}

/// <summary>application/x-www-form-urlencoded helpers.</summary>
public static class QueryString
{
    public static string Build(IEnumerable<KeyValuePair<string, string>> parameters)
    {
        var sb = new StringBuilder();
        foreach (var (k, v) in parameters)
        {
            if (sb.Length > 0)
            {
                sb.Append('&');
            }
            sb.Append(Uri.EscapeDataString(k)).Append('=').Append(Uri.EscapeDataString(v));
        }
        return sb.ToString();
    }

    /// <summary>Parses a query string (leading '?' allowed). The first occurrence of a name wins.</summary>
    public static IReadOnlyDictionary<string, string> Parse(string? query)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        if (string.IsNullOrEmpty(query))
        {
            return result;
        }
        if (query[0] == '?')
        {
            query = query[1..];
        }
        foreach (var part in query.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = part.IndexOf('=');
            var name = Decode(eq < 0 ? part : part[..eq]);
            var value = eq < 0 ? "" : Decode(part[(eq + 1)..]);
            result.TryAdd(name, value);
        }
        return result;
    }

    private static string Decode(string s) => Uri.UnescapeDataString(s.Replace('+', ' '));
}
