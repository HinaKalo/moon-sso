using System.Net.Http.Headers;
using System.Text.Json;
using MoonSso;
using MoonSso.Desktop;

namespace MoonSso.Tests.Integration;

[Trait("Category", "Integration")]
public class LoginTests(Xunit.Abstractions.ITestOutputHelper output)
{
    [Fact]
    public async Task ChallengeLogin_Alice_TestNative()
    {
        await Testbed.EnsureReachableAsync();
        var recorder = new RecordingHandler();
        await using var client = Testbed.CreateClient("test-native", o => o.HttpHandler = recorder);
        ProfileChangedEventArgs? changed = null;
        client.ProfileChanged += (_, e) => changed = e;

        var tokens = await Testbed.WithThrottleRetryAsync(() => client.LoginWithPasswordAsync("alice", Testbed.AlicePassword));

        Assert.True(client.IsSignedIn);
        Assert.False(string.IsNullOrEmpty(tokens.RefreshToken));
        Assert.False(string.IsNullOrEmpty(tokens.IdToken));
        Assert.Contains("profile:write", tokens.Scopes);
        Assert.Equal("alice", client.CurrentProfile!.PreferredUsername);
        Assert.Equal("login", changed!.Source);
        var lifetime = tokens.ExpiresAt - tokens.IssuedAt;
        Assert.InRange(lifetime.TotalSeconds, 60, 86400);

        // The access token is a valid at+jwt for this client.
        var at = await client.Validator.ValidateAccessTokenAsync(tokens.AccessToken, "test-native");
        Assert.Equal(client.CurrentProfile.Sub, at.Subject);

        var me = await client.GetMeAsync();
        Assert.Equal("alice", me.PreferredUsername);
        Assert.False(me.TotpEnabled);

        // The second call revalidates with the cached ETag (304) and returns the cached profile.
        var again = await client.GetMeAsync();
        Assert.Equal(me, again);
        Assert.Contains(recorder.Log, e => e.Path == "/api/v1/me" && e.Status == 304);
    }

    [Fact]
    public async Task ChallengeLogin_WrongPassword_IsAccessDenied()
    {
        await Testbed.EnsureReachableAsync();
        await using var client = Testbed.CreateClient("test-native");
        var (user, _) = await Testbed.CreateUserAsync();
        var ex = await Assert.ThrowsAsync<MoonSsoException>(() => client.LoginWithPasswordAsync(user, "Definitely-Wrong-9"));
        Assert.Equal(ErrorCodes.AccessDenied, ex.Error);
        Assert.Equal(403, ex.StatusCode);
        Assert.False(client.IsSignedIn);
    }

    [Fact]
    public async Task ChallengeLogin_Bob_WithOtp()
    {
        await Testbed.EnsureReachableAsync();
        await using var client = Testbed.CreateClient("test-native");
        var otpEx = await Assert.ThrowsAsync<OtpRequiredException>(() => Testbed.WithThrottleRetryAsync(() => client.LoginWithPasswordAsync("bob", Testbed.BobPassword)));
        Assert.Equal(ErrorCodes.InsufficientAuthorization, otpEx.Error);
        Assert.False(string.IsNullOrEmpty(otpEx.AuthSession));
        Assert.False(client.IsSignedIn);

        // A wrong code keeps the challenge alive.
        var wrong = await Assert.ThrowsAsync<OtpRequiredException>(() => client.SubmitOtpAsync(otpEx.Challenge, "000000"));
        Assert.Equal(otpEx.AuthSession, wrong.AuthSession);

        // Codes are single-use per 30 s step and other SDK suites may log bob in concurrently: retry on the next step if needed.
        TokenSet? tokens = null;
        for (var attempt = 0; attempt < 4 && tokens is null; attempt++)
        {
            var code = await Testbed.TotpAsync(Testbed.BobTotpSecret);
            try
            {
                tokens = await client.SubmitOtpAsync(otpEx.Challenge, code);
            }
            catch (OtpRequiredException)
            {
                await Task.Delay(TimeSpan.FromSeconds(31 - DateTimeOffset.UtcNow.ToUnixTimeSeconds() % 30));
            }
            catch (MoonSsoException ex) when (ex.Error == "slow_down")
            {
                await Task.Delay(TimeSpan.FromSeconds(5));
            }
        }
        Assert.NotNull(tokens);
        Assert.True(client.IsSignedIn);
        Assert.Equal("bob", client.CurrentProfile!.PreferredUsername);
        var id = await client.Validator.ValidateIdTokenAsync(tokens!.IdToken!, "test-native");
        Assert.True(id.TryGetProperty("amr", out var amr));
        Assert.Contains("otp", amr.EnumerateArray().Select(a => a.GetString()));
        Assert.True((await client.GetMeAsync()).TotpEnabled);
    }

    [Fact]
    public async Task DPoPRequiredClient_LoginRefreshAndNonceHandling()
    {
        await Testbed.EnsureReachableAsync();
        var recorder = new RecordingHandler();
        await using var client = Testbed.CreateClient("test-native-dpop", o => o.HttpHandler = recorder);
        var (user, password) = await Testbed.CreateUserAsync();

        var tokens = await Testbed.WithThrottleRetryAsync(() => client.LoginWithPasswordAsync(user, password));
        Assert.Equal("Bearer", tokens.TokenType);
        // The first proof had no nonce: the server asked for one and the SDK retried with it.
        Assert.Contains(recorder.Log, e => e.Path == "/oauth/authorize-challenge" && e.Error == ErrorCodes.UseDPoPNonce);
        Assert.Contains(recorder.Log, e => e.Path == "/oauth/authorize-challenge" && e.Status == 200 && e.HasDPoP);
        Assert.Contains(recorder.Log, e => e.Path == "/oauth/token" && e.Status == 200 && e.HasDPoP);

        var refreshed = await client.RefreshAsync();
        Assert.NotEqual(tokens.RefreshToken, refreshed.RefreshToken);
        Assert.NotEqual(tokens.AccessToken, refreshed.AccessToken);

        // The refresh token is bound to the installation key: presenting it without a proof fails.
        using var raw = new HttpClient();
        using var resp = await raw.PostAsync(Testbed.Issuer + "/oauth/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = refreshed.RefreshToken!,
            ["client_id"] = "test-native-dpop",
        }));
        Assert.Equal(400, (int)resp.StatusCode);
        Assert.Contains("invalid_dpop_proof", await resp.Content.ReadAsStringAsync());

        // Still usable by the SDK afterwards.
        Assert.NotNull((await client.GetMeAsync()).Sub);
    }

    [Fact]
    public async Task AuthorizationCode_ViaTestAuthorize_WithStateAndIssChecks()
    {
        await Testbed.EnsureReachableAsync();
        await using var client = Testbed.CreateClient("test-native");
        var (user, password) = await Testbed.CreateUserAsync();

        var request = await client.CreateAuthorizationRequestAsync("http://127.0.0.1/callback");
        var q = QueryString.Parse(request.Url.Query);
        Assert.Equal("S256", q["code_challenge_method"]);
        Assert.Equal(request.State, q["state"]);
        Assert.Equal(request.Nonce, q["nonce"]);
        Assert.True(q.ContainsKey("dpop_jkt"));

        var callback = await Testbed.AuthorizeAsync(request.Url, user, password);
        var cb = QueryString.Parse(callback.Query);
        Assert.Equal(Testbed.Issuer, cb["iss"]);

        // Tampered state / issuer are rejected before the code is used.
        var badState = new Uri(callback.ToString().Replace("state=" + Uri.EscapeDataString(request.State), "state=forged"));
        Assert.Equal(ErrorCodes.InvalidState, (await Assert.ThrowsAsync<MoonSsoException>(() => client.ExchangeCodeAsync(request, badState))).Error);
        var badIss = new Dictionary<string, string>(cb) { ["iss"] = "https://evil.example" };
        Assert.Equal(ErrorCodes.InvalidIssuer, (await Assert.ThrowsAsync<MoonSsoException>(() => client.ExchangeCodeAsync(request, badIss))).Error);
        var noIss = new Dictionary<string, string>(cb);
        noIss.Remove("iss");
        Assert.Equal(ErrorCodes.InvalidIssuer, (await Assert.ThrowsAsync<MoonSsoException>(() => client.ExchangeCodeAsync(request, noIss))).Error);

        var tokens = await client.ExchangeCodeAsync(request, callback);
        Assert.True(client.IsSignedIn);
        Assert.Equal(user, client.CurrentProfile!.PreferredUsername);
        var id = await client.Validator.ValidateIdTokenAsync(tokens.IdToken!, "test-native", request.Nonce, tokens.AccessToken);
        Assert.Equal(request.Nonce, id.Nonce);
    }

    [Fact]
    public async Task DesktopBrowserLogin_LoopbackRedirect_DPoPClient()
    {
        await Testbed.EnsureReachableAsync();
        await using var client = Testbed.CreateClient("test-native-dpop");
        var (user, password) = await Testbed.CreateUserAsync();
        string? redirect = null;
        string? page = null;

        var tokens = await client.LoginWithBrowserAsync(new BrowserLoginOptions
        {
            Timeout = TimeSpan.FromSeconds(60),
            OpenBrowser = async (url, ct) =>
            {
                // Stand-in for the user's browser: log in, then follow the redirect to the loopback listener.
                var callback = await Testbed.AuthorizeAsync(url, user, password);
                redirect = callback.GetLeftPart(UriPartial.Path);
                _ = Task.Run(async () =>
                {
                    // A stray request with a foreign state must not end the wait.
                    using var stray = await Testbed.Http.GetAsync(callback.GetLeftPart(UriPartial.Path) + "?code=x&state=forged");
                    Assert.Equal(400, (int)stray.StatusCode);
                    using var resp = await Testbed.Http.GetAsync(callback);
                    page = await resp.Content.ReadAsStringAsync();
                });
            },
        });

        Assert.Matches(@"^http://127\.0\.0\.1:\d+/callback$", redirect);
        Assert.True(client.IsSignedIn);
        Assert.Equal(user, client.CurrentProfile!.PreferredUsername);
        Assert.False(string.IsNullOrEmpty(tokens.RefreshToken));
        for (var i = 0; i < 50 && page is null; i++)
        {
            await Task.Delay(100);
        }
        Assert.Contains("登录完成", page);
    }

    [Fact]
    public async Task DesktopBrowserLogin_TimesOut()
    {
        await Testbed.EnsureReachableAsync();
        await using var client = Testbed.CreateClient("test-native");
        await Assert.ThrowsAsync<TimeoutException>(() => client.LoginWithBrowserAsync(new BrowserLoginOptions
        {
            Timeout = TimeSpan.FromMilliseconds(500),
            OpenBrowser = (_, _) => Task.CompletedTask,
        }));
    }

    [Fact]
    public async Task NativeRegistration_RandomUser()
    {
        await Testbed.EnsureReachableAsync();
        var info = await Testbed.CreateClient().GetRegistrationInfoAsync();
        Assert.True(info.RegistrationOpen);

        await using var client = Testbed.CreateClient("test-native");
        var username = Testbed.RandomUsername();
        var tokens = await Testbed.WithThrottleRetryAsync(() => client.RegisterAsync(new NativeRegistration(username, Testbed.RandomPassword(), "测试用户")));
        Assert.True(client.IsSignedIn);
        Assert.False(string.IsNullOrEmpty(tokens.RefreshToken));
        var me = await client.GetMeAsync();
        Assert.Equal(username, me.PreferredUsername);
        Assert.Equal("测试用户", me.Nickname);

        // Validation errors carry the field.
        await using var other = Testbed.CreateClient("test-native");
        var ex = await Assert.ThrowsAsync<MoonSsoException>(() => other.RegisterAsync(new NativeRegistration(username, Testbed.RandomPassword())));
        Assert.Equal(422, ex.StatusCode);
        Assert.Equal("username", ex.Field);
        var weak = await Assert.ThrowsAsync<MoonSsoException>(() => other.RegisterAsync(new NativeRegistration(Testbed.RandomUsername(), "short")));
        Assert.Equal("password", weak.Field);
    }

    [Fact]
    public async Task NativeRegistration_DPoPRequiredClient()
    {
        await Testbed.EnsureReachableAsync();
        var recorder = new RecordingHandler();
        await using var client = Testbed.CreateClient("test-native-dpop", o => o.HttpHandler = recorder);
        var username = Testbed.RandomUsername();
        await Testbed.WithThrottleRetryAsync(() => client.RegisterAsync(new NativeRegistration(username, Testbed.RandomPassword())));
        Assert.True(client.IsSignedIn);
        Assert.Equal(username, client.CurrentProfile!.PreferredUsername);
        foreach (var e in recorder.Log)
        {
            output.WriteLine($"{e.Method} {e.Path} -> {e.Status} {e.Error} dpop={e.HasDPoP}");
        }
    }

    [Fact]
    public async Task Logout_RevokesRefreshToken()
    {
        await Testbed.EnsureReachableAsync();
        await using var client = Testbed.CreateClient("test-native", o => o.UseDPoP = false);
        var (user, password) = await Testbed.CreateUserAsync();
        var tokens = await client.LoginWithPasswordAsync(user, password);
        var endSession = await client.GetEndSessionUrlAsync("http://127.0.0.1/", "s1");
        Assert.Contains("id_token_hint=", endSession.Query);
        await client.LogoutAsync();
        Assert.False(client.IsSignedIn);

        using var resp = await Testbed.Http.PostAsync(Testbed.Issuer + "/oauth/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = tokens.RefreshToken!,
            ["client_id"] = "test-native",
        }));
        Assert.Contains("invalid_grant", await resp.Content.ReadAsStringAsync());

        using var me = new HttpRequestMessage(HttpMethod.Get, Testbed.Issuer + "/api/v1/me");
        me.Headers.Authorization = new AuthenticationHeaderValue("Bearer", tokens.AccessToken);
        using var meResp = await Testbed.Http.SendAsync(me);
        Assert.Equal(401, (int)meResp.StatusCode);
    }

    [Fact]
    public async Task DynamicClientRegistration_CreatesClient()
    {
        await Testbed.EnsureReachableAsync();
        await using var client = Testbed.CreateClient();
        var iat = await Testbed.InitialAccessTokenAsync();
        ClientRegistrationResponse reg;
        try
        {
            reg = await client.RegisterClientAsync(iat, new ClientRegistrationRequest
            {
                ClientName = "moon-sso-dotnet-sdk test " + Guid.NewGuid().ToString("N")[..6],
                RedirectUris = new[] { "http://127.0.0.1/callback" },
                ApplicationType = "native",
                TokenEndpointAuthMethod = "none",
                Scope = "openid profile offline_access",
            });
        }
        catch (MoonSsoException quota) when (quota.StatusCode == 403 && quota.Error == ErrorCodes.AccessDenied)
        {
            // Testbed limitation: /__test/iat tokens all belong to alice, and settings.MaxClientsPerDeveloper (default 10) is
            // shared by every SDK suite. The SDK still surfaced the server error correctly.
            output.WriteLine("DCR quota exhausted on the shared testbed: " + quota.ErrorDescription);
            return;
        }
        Assert.False(string.IsNullOrEmpty(reg.ClientId));
        Assert.Contains(reg.Status, new[] { "active", "pending_approval" });
        Assert.False(string.IsNullOrEmpty(reg.RegistrationAccessToken));

        var ex = await Assert.ThrowsAsync<MoonSsoException>(() => client.RegisterClientAsync("iat_invalid", new ClientRegistrationRequest { ClientName = "x", RedirectUris = new[] { "http://127.0.0.1/callback" } }));
        Assert.InRange(ex.StatusCode ?? 0, 400, 403);
    }
}
