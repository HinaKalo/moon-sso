using System.Security.Cryptography;
using MoonSso;
using MoonSso.Desktop;

namespace MoonSso.Tests.Unit;

public sealed class StorageTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "moonsso-tests-" + Guid.NewGuid().ToString("N"));

    private static StoredSession Sample()
    {
        using var key = DPoPKey.Generate();
        return new StoredSession
        {
            Tokens = new TokenSet
            {
                AccessToken = "eyJ.access",
                RefreshToken = "refresh-秘密",
                IdToken = "eyJ.id",
                Scope = "openid profile offline_access",
                IssuedAt = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000),
                ExpiresAt = DateTimeOffset.FromUnixTimeSeconds(1_800_000_600),
            },
            Profile = new UserProfile { Sub = "sub-1", PreferredUsername = "alice", Name = "爱丽丝", ProfileVersion = 7, TotpEnabled = true },
            ProfileETag = "\"pv-7\"",
            DPoPKey = key.Export(),
        };
    }

    private static async Task AssertRoundTrip(ITokenStore store)
    {
        Assert.Null(await store.LoadAsync());
        var s = Sample();
        await store.SaveAsync(s);
        var loaded = await store.LoadAsync();
        Assert.NotNull(loaded);
        Assert.Equal(s.Tokens, loaded!.Tokens);
        Assert.Equal(s.Profile, loaded.Profile);
        Assert.Equal(s.ProfileETag, loaded.ProfileETag);
        Assert.Equal(s.DPoPKey, loaded.DPoPKey);
        using (var k = DPoPKey.Import(loaded.DPoPKey!))
        {
            Assert.NotEmpty(k.Thumbprint);
        }
        var updated = s with { Tokens = s.Tokens! with { RefreshToken = "rotated" } };
        await store.SaveAsync(updated);
        Assert.Equal("rotated", (await store.LoadAsync())!.Tokens!.RefreshToken);
        await store.ClearAsync();
        Assert.Null(await store.LoadAsync());
    }

    [Fact]
    public Task InMemory_RoundTrip() => AssertRoundTrip(new InMemoryTokenStore());

    [Fact]
    public async Task PlainFile_RoundTrip_NoTempFilesLeft()
    {
        var store = new FileTokenStore(Path.Combine(_dir, "plain", "session.json"));
        await AssertRoundTrip(store);
        await store.SaveAsync(Sample());
        Assert.Single(Directory.GetFiles(Path.Combine(_dir, "plain")));
        if (!OperatingSystem.IsWindows())
        {
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(store.FilePath));
        }
    }

    [Fact]
    public async Task Dpapi_RoundTrip_EncryptsContent()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }
        var path = Path.Combine(_dir, "dpapi", "session.dat");
        var store = new DpapiTokenStore(path);
        await AssertRoundTrip(store);
        await store.SaveAsync(Sample());
        var raw = await File.ReadAllBytesAsync(path);
        var text = System.Text.Encoding.UTF8.GetString(raw);
        Assert.DoesNotContain("eyJ.access", text);
        Assert.DoesNotContain("refresh", text);
        // A corrupt file reads as "no session" instead of throwing.
        await File.WriteAllBytesAsync(path, new byte[] { 1, 2, 3 });
        Assert.Null(await store.LoadAsync());
    }

    [Fact]
    public async Task KeyWrappedStore_RoundTrip_AndLostKeyMeansSignedOut()
    {
        var provider = new MemoryKeyProvider();
        var path = Path.Combine(_dir, "wrapped", "session.dat");
        var store = new KeyWrappedFileTokenStore(path, provider);
        await AssertRoundTrip(store);
        await store.SaveAsync(Sample());
        Assert.DoesNotContain("refresh", System.Text.Encoding.UTF8.GetString(await File.ReadAllBytesAsync(path)));
        Assert.NotNull(await new KeyWrappedFileTokenStore(path, provider).LoadAsync());
        Assert.Null(await new KeyWrappedFileTokenStore(path, new MemoryKeyProvider()).LoadAsync());
    }

    [Fact]
    public async Task DesktopDefaults_RoundTrip()
    {
        var appId = "moonsso.tests." + Guid.NewGuid().ToString("N")[..8];
        var store = DesktopTokenStore.CreateDefault(appId);
        try
        {
            await AssertRoundTrip(store);
        }
        finally
        {
            await store.ClearAsync();
            Directory.Delete(DesktopTokenStore.GetDataDirectory(appId), recursive: true);
        }
        Assert.Throws<ArgumentException>(() => DesktopTokenStore.CreateDefault("../evil"));
    }

    [Fact]
    public async Task FileRefreshLock_IsExclusive()
        => await AssertExclusive(new FileRefreshLock(Path.Combine(_dir, "refresh.lock")));

    [Fact]
    public async Task NamedMutexLock_IsExclusive()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }
        await AssertExclusive(new NamedMutexRefreshLock("MoonSso.Tests." + Guid.NewGuid().ToString("N")));
        Assert.IsType<NamedMutexRefreshLock>(DesktopRefreshLock.CreateDefault("moonsso.tests"));
    }

    private static async Task AssertExclusive(IRefreshLock l)
    {
        var inside = 0;
        var maxInside = 0;
        var tasks = Enumerable.Range(0, 16).Select(_ => Task.Run(async () =>
        {
            await using (await l.AcquireAsync())
            {
                var n = Interlocked.Increment(ref inside);
                lock (l)
                {
                    maxInside = Math.Max(maxInside, n);
                }
                await Task.Delay(10);
                Interlocked.Decrement(ref inside);
            }
        }));
        await Task.WhenAll(tasks);
        Assert.Equal(1, maxInside);

        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(300));
        await using (await l.AcquireAsync())
        {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Task.Run(() => l.AcquireAsync(cts.Token)));
        }
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

    private sealed class MemoryKeyProvider : ISecretKeyProvider
    {
        private byte[]? _key;

        public Task<byte[]?> GetKeyAsync(bool create, CancellationToken cancellationToken)
        {
            if (_key is null && create)
            {
                _key = RandomNumberGenerator.GetBytes(32);
            }
            return Task.FromResult(_key);
        }

        public Task DeleteKeyAsync(CancellationToken cancellationToken)
        {
            _key = null;
            return Task.CompletedTask;
        }
    }
}
