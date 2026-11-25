using MoonSso;
using MoonSso.Internal;

namespace MoonSso.Tests.Unit;

public class TokenLifecycleTests
{
    [Fact]
    public async Task ConcurrentRefresh_IsSingleFlight()
    {
        var server = new FakeServer { TokenDelay = TimeSpan.FromMilliseconds(200) };
        var store = new InMemoryTokenStore();
        await store.SaveAsync(FakeServer.Session());
        await using var client = server.CreateClient(store, dpop: false);
        await client.InitializeAsync();

        var results = await Task.WhenAll(Enumerable.Range(0, 64).Select(_ => Task.Run(() => client.RefreshAsync())));

        Assert.Equal(1, server.TokenCalls);
        Assert.All(results, r => Assert.Equal("at-1", r.AccessToken));
        Assert.Equal("rt-1", (await store.LoadAsync())!.Tokens!.RefreshToken);
    }

    [Fact]
    public async Task RetriesOnceOn503_AndKeepsSessionOnTransientFailure()
    {
        var server = new FakeServer();
        server.TokenScript.Enqueue(() => FakeServer.Json(503, new { error = "temporarily_unavailable" }));
        var store = new InMemoryTokenStore();
        await store.SaveAsync(FakeServer.Session());
        await using var client = server.CreateClient(store, dpop: false);

        var t = await client.RefreshAsync();
        Assert.Equal(2, server.TokenCalls);
        Assert.Equal("at-1", t.AccessToken);
        var bodies = server.TokenBodies.ToArray();
        Assert.Equal(bodies[0], bodies[1]); // same parameters

        server.TokenScript.Enqueue(() => FakeServer.Json(502, new { }));
        server.TokenScript.Enqueue(() => new HttpResponseMessage(System.Net.HttpStatusCode.GatewayTimeout));
        var ex = await Assert.ThrowsAsync<MoonSsoException>(() => client.RefreshAsync());
        Assert.True(ex.IsTransient);
        Assert.Equal(4, server.TokenCalls); // exactly one retry
        Assert.True(client.IsSignedIn);
        Assert.Equal("rt-1", (await store.LoadAsync())!.Tokens!.RefreshToken);
    }

    [Fact]
    public async Task InvalidClient_IsNotRetried_AndDoesNotEndSession()
    {
        var server = new FakeServer();
        server.TokenScript.Enqueue(() => FakeServer.Json(401, new { error = "invalid_client" }));
        var store = new InMemoryTokenStore();
        await store.SaveAsync(FakeServer.Session());
        await using var client = server.CreateClient(store, dpop: false);
        var ex = await Assert.ThrowsAsync<MoonSsoException>(() => client.RefreshAsync());
        Assert.Equal(ErrorCodes.InvalidClient, ex.Error);
        Assert.Equal(1, server.TokenCalls);
        Assert.True(client.IsSignedIn);
    }

    [Fact]
    public async Task InvalidGrant_RaisesSessionExpired_KeepsDPoPKey()
    {
        var server = new FakeServer();
        server.TokenScript.Enqueue(() => FakeServer.Json(400, new { error = "invalid_grant", error_description = "刷新令牌已被吊销" }));
        var store = new InMemoryTokenStore();
        using var key = DPoPKey.Generate();
        await store.SaveAsync(FakeServer.Session(key: key.Export()));
        await using var client = server.CreateClient(store);
        var expired = new TaskCompletionSource<string>();
        client.SessionExpired += (_, e) => expired.TrySetResult(e.Reason);

        await Assert.ThrowsAsync<SessionExpiredException>(() => client.RefreshAsync());
        Assert.Equal("刷新令牌已被吊销", await expired.Task.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.False(client.IsSignedIn);
        var stored = await store.LoadAsync();
        Assert.Null(stored!.Tokens);
        Assert.Equal(key.Export().X, stored.DPoPKey!.X);
        await Assert.ThrowsAsync<NotSignedInException>(() => client.GetAccessTokenAsync());
    }

    [Fact]
    public async Task UseDPoPNonce_RetriesWithServerNonce()
    {
        var server = new FakeServer();
        server.TokenScript.Enqueue(() => FakeServer.Json(400, new { error = "use_dpop_nonce" }, dpopNonce: "server-nonce-1"));
        var store = new InMemoryTokenStore();
        await store.SaveAsync(FakeServer.Session());
        await using var client = server.CreateClient(store);
        await client.RefreshAsync();

        var proofs = server.DPoPProofs.ToArray();
        Assert.Equal(2, proofs.Length);
        var first = JwsToken.Parse(proofs[0]!);
        var second = JwsToken.Parse(proofs[1]!);
        Assert.False(first.Payload.TryGetProperty("nonce", out _));
        Assert.Equal("server-nonce-1", second.Payload.GetProperty("nonce").GetString());
        Assert.Equal(FakeServer.Issuer + "/oauth/token", second.Payload.GetProperty("htu").GetString());
        Assert.NotEqual(first.Payload.GetProperty("jti").GetString(), second.Payload.GetProperty("jti").GetString());

        // The next proof carries the nonce from the last successful response.
        await client.RefreshAsync();
        Assert.Equal("nonce-1", JwsToken.Parse(server.DPoPProofs.Last()!).Payload.GetProperty("nonce").GetString());
        // The generated key was persisted with the session.
        Assert.NotNull((await store.LoadAsync())!.DPoPKey);
    }

    [Fact]
    public async Task ProactiveRefresh_At75Percent_AndTransientFailureFallsBack()
    {
        var time = new FixedTime(DateTimeOffset.UtcNow);
        var server = new FakeServer();
        var store = new InMemoryTokenStore();
        await store.SaveAsync(FakeServer.Session(issuedAt: time.GetUtcNow(), lifetimeSeconds: 400));
        await using var client = server.CreateClient(store, time: time, dpop: false);

        time.Advance(TimeSpan.FromSeconds(299));
        Assert.Equal("at-0", await client.GetAccessTokenAsync());
        Assert.Equal(0, server.TokenCalls);

        time.Advance(TimeSpan.FromSeconds(2)); // 301 s of 400 s > 75 %
        Assert.Equal("at-1", await client.GetAccessTokenAsync());
        Assert.Equal(1, server.TokenCalls);

        // At 80 % with the server down, the still-valid token is returned.
        time.Advance(TimeSpan.FromSeconds(500));
        server.ExpiresIn = 600;
        server.TokenScript.Enqueue(() => FakeServer.Json(503, new { }));
        server.TokenScript.Enqueue(() => FakeServer.Json(503, new { }));
        // token at-1 was issued at t=301 for 600 s; now t=801 → 83 % used, still valid
        Assert.Equal("at-1", await client.GetAccessTokenAsync());
        Assert.True(client.IsSignedIn);
    }

    [Fact]
    public async Task SharedStore_SecondInstanceAdoptsInsteadOfRefreshing()
    {
        var server = new FakeServer();
        var store = new InMemoryTokenStore();
        await store.SaveAsync(FakeServer.Session());
        var sharedLock = new SemaphoreLock();
        await using var a = server.CreateClient(store, sharedLock, dpop: false);
        await using var b = server.CreateClient(store, sharedLock, dpop: false);
        await a.InitializeAsync();
        await b.InitializeAsync();

        var ra = await a.RefreshAsync();
        var adopted = new TaskCompletionSource<TokenSet?>();
        b.TokensChanged += (_, e) => adopted.TrySetResult(e.Tokens);
        // b still holds at-0; its forced refresh (e.g. after a 401) must adopt a's result instead of rotating again.
        var rb = await b.Tokens.RefreshAfterRejectionAsync("at-0");
        Assert.Equal(1, server.TokenCalls);
        Assert.Equal(ra.AccessToken, rb.AccessToken);
        Assert.Equal("rt-1", rb.RefreshToken);
        Assert.Equal("at-1", (await adopted.Task.WaitAsync(TimeSpan.FromSeconds(5)))!.AccessToken);
    }

    [Fact]
    public async Task SharedStore_SignOutInOtherInstanceEndsSession()
    {
        var server = new FakeServer();
        var store = new InMemoryTokenStore();
        await store.SaveAsync(FakeServer.Session());
        var sharedLock = new SemaphoreLock();
        await using var a = server.CreateClient(store, sharedLock, dpop: false);
        await using var b = server.CreateClient(store, sharedLock, dpop: false);
        await a.InitializeAsync();
        await b.InitializeAsync();
        var expired = new TaskCompletionSource<bool>();
        b.SessionExpired += (_, _) => expired.TrySetResult(true);
        await a.LogoutAsync();
        await Assert.ThrowsAsync<SessionExpiredException>(() => b.RefreshAsync());
        Assert.True(await expired.Task.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.Equal(0, server.TokenCalls);
    }

    [Fact]
    public async Task AuthHandler_RefreshesOn401AndReplaysOnce()
    {
        var server = new FakeServer();
        var store = new InMemoryTokenStore();
        await store.SaveAsync(FakeServer.Session(at: "stale-at"));
        await using var client = server.CreateClient(store, dpop: false);
        using var http = new HttpClient(new MoonSsoAuthHandler(client) { InnerHandler = server });
        using var resp = await http.PostAsync(FakeServer.Issuer + "/api/v1/me", new StringContent("{\"x\":1}"));
        Assert.Equal(System.Net.HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal(1, server.TokenCalls);

        // A token the server keeps rejecting: one refresh, one replay, then the 401 is returned.
        server.ValidAccessTokens.Clear();
        server.TokenScript.Enqueue(() => FakeServer.Json(200, new { access_token = "never-valid", expires_in = 600, refresh_token = "rt-x" }));
        using var resp2 = await http.GetAsync(FakeServer.Issuer + "/api/v1/me");
        Assert.Equal(System.Net.HttpStatusCode.Unauthorized, resp2.StatusCode);
        Assert.Equal(2, server.TokenCalls);
        Assert.True(client.IsSignedIn);
    }

    [Fact]
    public async Task GetMe_UpdatesProfileAndRaisesEvent()
    {
        var server = new FakeServer();
        var store = new InMemoryTokenStore();
        await store.SaveAsync(FakeServer.Session(at: "at-0"));
        server.ValidAccessTokens["at-0"] = true;
        await using var client = server.CreateClient(store, dpop: false);
        var changed = new TaskCompletionSource<ProfileChangedEventArgs>();
        client.ProfileChanged += (_, e) => changed.TrySetResult(e);
        var me = await client.GetMeAsync();
        Assert.Equal("alice", me.PreferredUsername);
        var evt = await changed.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal("api", evt.Source);
        Assert.Equal(2, (await store.LoadAsync())!.Profile!.ProfileVersion);
        Assert.Equal("\"pv-2\"", (await store.LoadAsync())!.ProfileETag);
    }

    [Fact]
    public async Task DynamicClientRegistration_SendsMetadataAndParsesResponse()
    {
        var server = new FakeServer();
        await using var client = server.CreateClient(new InMemoryTokenStore());
        var reg = await client.RegisterClientAsync("iat_good", new ClientRegistrationRequest
        {
            ClientName = "x",
            RedirectUris = new[] { "http://127.0.0.1/callback" },
            ApplicationType = "native",
            TokenEndpointAuthMethod = "none",
        });
        Assert.Equal("dcr-1", reg.ClientId);
        Assert.Equal("pending_approval", reg.Status);
        Assert.Equal("rat", reg.RegistrationAccessToken);
        using var doc = System.Text.Json.JsonDocument.Parse(server.LastRegistrationBody!);
        Assert.Equal("native", doc.RootElement.GetProperty("application_type").GetString());
        Assert.False(doc.RootElement.TryGetProperty("webhook_url", out _)); // nulls are omitted
        var ex = await Assert.ThrowsAsync<MoonSsoException>(() => client.RegisterClientAsync("iat_bad", new ClientRegistrationRequest { ClientName = "x" }));
        Assert.Equal(401, ex.StatusCode);
    }

    private sealed class SemaphoreLock : IRefreshLock
    {
        private readonly SemaphoreSlim _s = new(1, 1);

        public async Task<IAsyncDisposable> AcquireAsync(CancellationToken cancellationToken = default)
        {
            await _s.WaitAsync(cancellationToken);
            return new Releaser(_s);
        }

        private sealed class Releaser(SemaphoreSlim s) : IAsyncDisposable
        {
            public ValueTask DisposeAsync()
            {
                s.Release();
                return ValueTask.CompletedTask;
            }
        }
    }
}
