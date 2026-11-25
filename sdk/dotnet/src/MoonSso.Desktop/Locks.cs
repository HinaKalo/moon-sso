using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

namespace MoonSso.Desktop;

/// <summary>
/// Cross-process refresh lock backed by a Windows named mutex (<c>Local\</c> namespace = current logon session).
/// A mutex is owned by a thread, so it is acquired and released on a dedicated thread; an abandoned mutex (crashed holder) is taken over.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class NamedMutexRefreshLock : IRefreshLock
{
    public NamedMutexRefreshLock(string name, TimeSpan? timeout = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        Name = name.Contains('\\', StringComparison.Ordinal) ? name : "Local\\" + name;
        Timeout = timeout ?? TimeSpan.FromMinutes(2);
    }

    public string Name { get; }

    public TimeSpan Timeout { get; }

    public Task<IAsyncDisposable> AcquireAsync(CancellationToken cancellationToken = default)
    {
        var acquired = new TaskCompletionSource<IAsyncDisposable>(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new ManualResetEventSlim(false);
        var thread = new Thread(() =>
        {
            Mutex? mutex = null;
            var owned = false;
            try
            {
                mutex = new Mutex(false, Name);
                var deadline = DateTime.UtcNow + Timeout;
                while (!owned)
                {
                    if (cancellationToken.IsCancellationRequested)
                    {
                        acquired.TrySetCanceled(cancellationToken);
                        return;
                    }
                    if (DateTime.UtcNow > deadline)
                    {
                        acquired.TrySetException(new MoonSsoException(ErrorCodes.LockTimeout, "Timed out waiting for the token refresh lock."));
                        return;
                    }
                    try
                    {
                        owned = mutex.WaitOne(100);
                    }
                    catch (AbandonedMutexException)
                    {
                        owned = true; // previous holder died; the store is written atomically, so it is consistent
                    }
                }
                acquired.TrySetResult(new Releaser(release));
                release.Wait();
            }
            catch (Exception ex)
            {
                acquired.TrySetException(ex);
            }
            finally
            {
                if (owned)
                {
                    mutex!.ReleaseMutex();
                }
                mutex?.Dispose();
                release.Dispose();
            }
        })
        {
            IsBackground = true,
            Name = "MoonSso refresh lock",
        };
        thread.Start();
        return acquired.Task;
    }

    private sealed class Releaser : IAsyncDisposable
    {
        private ManualResetEventSlim? _release;

        public Releaser(ManualResetEventSlim release) => _release = release;

        public ValueTask DisposeAsync()
        {
            Interlocked.Exchange(ref _release, null)?.Set();
            return ValueTask.CompletedTask;
        }
    }
}

/// <summary>Chooses the cross-process refresh lock for a desktop app.</summary>
public static class DesktopRefreshLock
{
    /// <summary>Windows: named mutex; macOS/Linux: lock file next to the session.</summary>
    public static IRefreshLock CreateDefault(string appId)
    {
        DesktopTokenStore.ValidateAppId(appId);
        if (OperatingSystem.IsWindows())
        {
            // Mutex names are limited and case-sensitive; derive a stable name from the app id and user profile.
            var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(appId + "|" + DesktopTokenStore.GetDataDirectory(appId))))[..16];
            return new NamedMutexRefreshLock("MoonSso.Refresh." + hash);
        }
        return new FileRefreshLock(Path.Combine(DesktopTokenStore.GetDataDirectory(appId), "refresh.lock"));
    }
}

/// <summary>Creates Moon SSO clients configured for desktop apps.</summary>
public static class MoonSsoDesktop
{
    /// <summary>
    /// Creates a client with the OS secure token store and cross-process refresh lock for <paramref name="appId"/>
    /// (so several instances of the app share one session safely). DPoP is enabled (public client).
    /// </summary>
    /// <param name="issuer">E.g. <c>https://sso.moonl.cloud</c>.</param>
    /// <param name="clientId">The app's client_id.</param>
    /// <param name="appId">Stable application identifier used for storage locations.</param>
    /// <param name="configure">Further option changes (scope, EventContext, Logger...).</param>
    public static MoonSsoClient CreateClient(string issuer, string clientId, string appId, Action<MoonSsoOptions>? configure = null)
    {
        var options = new MoonSsoOptions { Issuer = issuer, ClientId = clientId };
        configure?.Invoke(options);
        options.TokenStore ??= DesktopTokenStore.CreateDefault(appId, options.Logger);
        options.RefreshLock ??= DesktopRefreshLock.CreateDefault(appId);
        return new MoonSsoClient(options);
    }
}
