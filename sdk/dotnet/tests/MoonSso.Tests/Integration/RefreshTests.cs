using System.Text.Json;
using MoonSso;
using MoonSso.Desktop;

namespace MoonSso.Tests.Integration;

[Trait("Category", "Integration")]
public sealed class RefreshTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "moonsso-it-" + Guid.NewGuid().ToString("N"));

    [Fact]
    public async Task RefreshRotation_PersistsNewRefreshToken()
    {
        await Testbed.EnsureReachableAsync();
        var store = new InMemoryTokenStore();
        await using var client = Testbed.CreateClient("test-native", o => o.TokenStore = store);
        var (user, password) = await Testbed.CreateUserAsync();
        var first = await client.LoginWithPasswordAsync(user, password);
        Assert.Equal(first.RefreshToken, (await store.LoadAsync())!.Tokens!.RefreshToken);

        var changes = 0;
        client.TokensChanged += (_, _) => Interlocked.Increment(ref changes);
        var second = await client.RefreshAsync();
        var third = await client.RefreshAsync();
        Assert.NotEqual(first.RefreshToken, second.RefreshToken);
        Assert.NotEqual(second.RefreshToken, third.RefreshToken);
        Assert.Equal(third.RefreshToken, (await store.LoadAsync())!.Tokens!.RefreshToken);
        Assert.Equal(2, changes);
        Assert.NotNull(third.IdToken);

        // A new client instance restores the session from the store.
        await using var restored = Testbed.CreateClient("test-native", o => o.TokenStore = store);
        Assert.True(await restored.InitializeAsync());
        Assert.Equal(user, (await restored.GetMeAsync()).PreferredUsername);
    }

    [Fact]
    public async Task ServerGraceWindow_ReturnsSameSuccessorForReplayedRefreshToken()
    {
        await Testbed.EnsureReachableAsync();
        await using var client = Testbed.CreateClient("test-native", o => o.UseDPoP = false);
        var (user, password) = await Testbed.CreateUserAsync();
        var tokens = await client.LoginWithPasswordAsync(user, password);

        async Task<string> RawRefresh()
        {
            using var resp = await Testbed.Http.PostAsync(Testbed.Issuer + "/oauth/token", new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["refresh_token"] = tokens.RefreshToken!,
                ["client_id"] = "test-native",
            }));
            var body = await resp.Content.ReadAsStringAsync();
            Assert.True(resp.IsSuccessStatusCode, body);
            using var doc = JsonDocument.Parse(body);
            return doc.RootElement.GetProperty("refresh_token").GetString()!;
        }

        var a = await RawRefresh();
        var b = await RawRefresh();
        Assert.Equal(a, b);
        Assert.NotEqual(tokens.RefreshToken, a);
    }

    [Fact]
    public async Task ConcurrentRefresh_ManyTasks_ConvergeOnOneRotation()
    {
        await Testbed.EnsureReachableAsync();
        var recorder = new RecordingHandler();
        await using var client = Testbed.CreateClient("test-native-dpop", o => o.HttpHandler = recorder);
        var (user, password) = await Testbed.CreateUserAsync();
        await client.LoginWithPasswordAsync(user, password);
        var tokenPostsBefore = recorder.Count("/oauth/token");

        var results = await Task.WhenAll(Enumerable.Range(0, 100).Select(_ => Task.Run(() => client.RefreshAsync())));

        Assert.Single(results.Select(r => r.RefreshToken).Distinct());
        Assert.Single(results.Select(r => r.AccessToken).Distinct());
        var successfulTokenPosts = recorder.Log.Count(e => e.Path == "/oauth/token" && e.Status == 200) - 1; // minus the login exchange
        Assert.Equal(1, successfulTokenPosts);
        Assert.InRange(recorder.Count("/oauth/token") - tokenPostsBefore, 1, 2); // 2 when a nonce retry was needed

        // The converged session keeps working.
        var next = await client.RefreshAsync();
        Assert.NotEqual(results[0].RefreshToken, next.RefreshToken);
    }

    [Fact]
    public async Task CrossInstance_SharedSecureStore_ConvergesWithoutReuse()
    {
        await Testbed.EnsureReachableAsync();
        Directory.CreateDirectory(_dir);
        ITokenStore Store() => OperatingSystem.IsWindows()
            ? new DpapiTokenStore(Path.Combine(_dir, "session.dat"))
            : new FileTokenStore(Path.Combine(_dir, "session.json"));
        IRefreshLock Lock() => OperatingSystem.IsWindows()
            ? new NamedMutexRefreshLock("MoonSso.Tests." + Path.GetFileName(_dir))
            : new FileRefreshLock(Path.Combine(_dir, "refresh.lock"));

        var recorder = new RecordingHandler();
        var (user, password) = await Testbed.CreateUserAsync();
        await using (var login = Testbed.CreateClient("test-native-dpop", o => { o.TokenStore = Store(); o.RefreshLock = Lock(); }))
        {
            await login.LoginWithPasswordAsync(user, password);
        }

        // Five "processes", each with its own store/lock objects and HTTP stack, sharing the same files.
        var instances = Enumerable.Range(0, 5).Select(_ => Testbed.CreateClient("test-native-dpop", o =>
        {
            o.TokenStore = Store();
            o.RefreshLock = Lock();
            o.HttpHandler = recorder;
        })).ToList();
        try
        {
            foreach (var i in instances)
            {
                Assert.True(await i.InitializeAsync());
            }
            var stale = instances[0].Tokens.Current!.AccessToken;
            var all = await Task.WhenAll(instances.SelectMany(i => Enumerable.Range(0, 10).Select(_ => Task.Run(() => i.Tokens.RefreshAfterRejectionAsync(stale)))));

            Assert.Single(all.Select(t => t.RefreshToken).Distinct());
            Assert.Equal(1, recorder.Log.Count(e => e.Path == "/oauth/token" && e.Status == 200));
            foreach (var i in instances)
            {
                Assert.Equal(all[0].RefreshToken, i.Tokens.Current!.RefreshToken);
            }

            // Every instance can keep refreshing (no reuse detection was triggered).
            var after = await instances[3].RefreshAsync();
            Assert.Equal(user, (await instances[1].GetMeAsync()).PreferredUsername);
            Assert.Equal(after.RefreshToken, (await Store().LoadAsync())!.Tokens!.RefreshToken);
        }
        finally
        {
            foreach (var i in instances)
            {
                await i.DisposeAsync();
            }
        }
    }

    [Fact]
    public async Task ProactiveRefresh_BeforeCall_WhenThresholdPassed()
    {
        await Testbed.EnsureReachableAsync();
        var store = new InMemoryTokenStore();
        var (user, password) = await Testbed.CreateUserAsync();
        await using (var login = Testbed.CreateClient("test-native", o => o.TokenStore = store))
        {
            await login.LoginWithPasswordAsync(user, password);
        }
        // Pretend the machine slept: 90 % of the lifetime is gone.
        var s = (await store.LoadAsync())!;
        var t = s.Tokens!;
        var lifetime = t.ExpiresAt - t.IssuedAt;
        await store.SaveAsync(s with { Tokens = t with { IssuedAt = DateTimeOffset.UtcNow - lifetime * 0.9, ExpiresAt = DateTimeOffset.UtcNow + lifetime * 0.1 } });

        await using var client = Testbed.CreateClient("test-native", o => o.TokenStore = store);
        await client.InitializeAsync();
        var me = await client.GetMeAsync();
        Assert.Equal(user, me.PreferredUsername);
        Assert.NotEqual(t.RefreshToken, client.Tokens.Current!.RefreshToken);
        Assert.NotEqual(t.AccessToken, client.Tokens.Current.AccessToken);
    }

    [Fact]
    public async Task RejectedAccessToken_IsRefreshedAndReplayedOnce()
    {
        await Testbed.EnsureReachableAsync();
        var store = new InMemoryTokenStore();
        var (user, password) = await Testbed.CreateUserAsync();
        await using (var login = Testbed.CreateClient("test-native", o => o.TokenStore = store))
        {
            await login.LoginWithPasswordAsync(user, password);
        }
        var s = (await store.LoadAsync())!;
        await store.SaveAsync(s with { Tokens = s.Tokens! with { AccessToken = "eyJhbGciOiJFUzI1NiJ9.e30.invalid" } });

        var recorder = new RecordingHandler();
        await using var client = Testbed.CreateClient("test-native", o => { o.TokenStore = store; o.HttpHandler = recorder; });
        var me = await client.GetMeAsync();
        Assert.Equal(user, me.PreferredUsername);
        Assert.Equal(2, recorder.Log.Count(e => e.Path == "/api/v1/me"));
        Assert.Contains(recorder.Log, e => e.Path == "/api/v1/me" && e.Status == 401);
    }

    [Fact]
    public async Task RevokedSession_RaisesSessionExpired()
    {
        await Testbed.EnsureReachableAsync();
        await using var client = Testbed.CreateClient("test-native", o => o.UseDPoP = false);
        var (user, password) = await Testbed.CreateUserAsync();
        var tokens = await client.LoginWithPasswordAsync(user, password);
        var expired = new TaskCompletionSource<SessionExpiredEventArgs>();
        client.SessionExpired += (_, e) => expired.TrySetResult(e);

        using (var revoke = await Testbed.Http.PostAsync(Testbed.Issuer + "/oauth/revoke", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["token"] = tokens.RefreshToken!,
            ["client_id"] = "test-native",
        })))
        {
            revoke.EnsureSuccessStatusCode();
        }

        await Assert.ThrowsAsync<SessionExpiredException>(() => client.RefreshAsync());
        var args = await expired.Task.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.False(string.IsNullOrEmpty(args.Reason));
        Assert.False(client.IsSignedIn);
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_dir, recursive: true);
        }
        catch (DirectoryNotFoundException)
        {
        }
    }
}
