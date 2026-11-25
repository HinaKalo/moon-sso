using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Serialization;
using MoonSso.Internal;

namespace MoonSso;

/// <summary>
/// Everything persisted for a client installation: tokens, cached profile and the DPoP private key.
/// The DPoP key survives sign-out (one key per installation).
/// </summary>
public sealed record StoredSession
{
    [JsonPropertyName("version")] public int Version { get; init; } = 1;
    [JsonPropertyName("tokens")] public TokenSet? Tokens { get; init; }
    [JsonPropertyName("profile")] public UserProfile? Profile { get; init; }
    [JsonPropertyName("profile_etag")] public string? ProfileETag { get; init; }
    [JsonPropertyName("dpop_key")] public DPoPKeyData? DPoPKey { get; init; }

    public override string ToString() => $"StoredSession {{ SignedIn = {Tokens is not null}, Sub = {Profile?.Sub} }}";
}

/// <summary>
/// Persistent storage for the session. Implementations must write atomically (a reader never observes a partial write).
/// Saves happen while the SDK holds the <see cref="IRefreshLock"/>, so a store shared by several processes stays consistent.
/// </summary>
public interface ITokenStore
{
    /// <summary>Returns the stored session, or null if nothing is stored.</summary>
    Task<StoredSession?> LoadAsync(CancellationToken cancellationToken = default);

    /// <summary>Atomically replaces the stored session.</summary>
    Task SaveAsync(StoredSession session, CancellationToken cancellationToken = default);

    /// <summary>Removes everything (including the DPoP key).</summary>
    Task ClearAsync(CancellationToken cancellationToken = default);
}

/// <summary>Keeps the session in memory only (lost when the process exits).</summary>
public sealed class InMemoryTokenStore : ITokenStore
{
    private StoredSession? _session;

    public Task<StoredSession?> LoadAsync(CancellationToken cancellationToken = default) => Task.FromResult(Volatile.Read(ref _session));

    public Task SaveAsync(StoredSession session, CancellationToken cancellationToken = default)
    {
        Volatile.Write(ref _session, session);
        return Task.CompletedTask;
    }

    public Task ClearAsync(CancellationToken cancellationToken = default)
    {
        Volatile.Write(ref _session, null);
        return Task.CompletedTask;
    }
}

/// <summary>
/// Stores the session as a file, written atomically (temp file + rename) with owner-only permissions (0600 on Unix).
/// Override <see cref="Protect"/> / <see cref="Unprotect"/> to encrypt the content (see the MoonSso.Desktop stores).
/// The plain implementation is only appropriate where the OS offers no secure storage.
/// </summary>
public class FileTokenStore : ITokenStore
{
    public FileTokenStore(string path)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        FilePath = Path.GetFullPath(path);
    }

    /// <summary>Location of the session file.</summary>
    public string FilePath { get; }

    /// <summary>Transforms the serialized session before it is written (default: none).</summary>
    protected virtual byte[] Protect(byte[] plaintext) => plaintext;

    /// <summary>Reverses <see cref="Protect"/>. Throw <see cref="System.Security.Cryptography.CryptographicException"/> when data cannot be decrypted.</summary>
    protected virtual byte[] Unprotect(byte[] data) => data;

    public virtual async Task<StoredSession?> LoadAsync(CancellationToken cancellationToken = default)
    {
        byte[] data;
        for (var attempt = 0; ; attempt++)
        {
            try
            {
                data = await File.ReadAllBytesAsync(FilePath, cancellationToken).ConfigureAwait(false);
                break;
            }
            catch (FileNotFoundException)
            {
                return null;
            }
            catch (DirectoryNotFoundException)
            {
                return null;
            }
            catch (IOException) when (attempt < 20)
            {
                // A concurrent atomic replace can briefly hold the file on Windows.
                await Task.Delay(25, cancellationToken).ConfigureAwait(false);
            }
        }
        if (data.Length == 0)
        {
            return null;
        }
        try
        {
            var plain = Unprotect(data);
            return JsonSerializer.Deserialize<StoredSession>(plain, Json.Options);
        }
        catch (Exception ex) when (ex is JsonException or System.Security.Cryptography.CryptographicException or FormatException)
        {
            // Unreadable (other user, new key, corruption): behave as "not signed in" rather than crash.
            return null;
        }
    }

    public virtual async Task SaveAsync(StoredSession session, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);
        var plain = JsonSerializer.SerializeToUtf8Bytes(session, Json.Options);
        var data = Protect(plain);
        if (!ReferenceEquals(data, plain))
        {
            Array.Clear(plain); // do not leave the plaintext session in memory longer than needed
        }
        await WriteAtomicAsync(FilePath, data, cancellationToken).ConfigureAwait(false);
    }

    public virtual Task ClearAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            File.Delete(FilePath);
        }
        catch (DirectoryNotFoundException)
        {
        }
        return Task.CompletedTask;
    }

    /// <summary>Writes <paramref name="data"/> to a sibling temp file with owner-only permissions and renames it over <paramref name="path"/>.</summary>
    protected internal static async Task WriteAtomicAsync(string path, byte[] data, CancellationToken cancellationToken)
    {
        var dir = Path.GetDirectoryName(path)!;
        CreatePrivateDirectory(dir);
        var tmp = Path.Combine(dir, "." + Path.GetFileName(path) + "." + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            var options = new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                Share = FileShare.None,
                Options = FileOptions.WriteThrough,
            };
            if (!OperatingSystem.IsWindows())
            {
                options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            }
            await using (var fs = new FileStream(tmp, options))
            {
                await fs.WriteAsync(data, cancellationToken).ConfigureAwait(false);
                await fs.FlushAsync(cancellationToken).ConfigureAwait(false);
                fs.Flush(flushToDisk: true);
            }
            // Retry a few times: on Windows a concurrent reader can briefly block the rename.
            for (var attempt = 0; ; attempt++)
            {
                try
                {
                    File.Move(tmp, path, overwrite: true);
                    break;
                }
                catch (Exception ex) when ((ex is IOException or UnauthorizedAccessException) && attempt < 20)
                {
                    await Task.Delay(25, cancellationToken).ConfigureAwait(false);
                }
            }
        }
        finally
        {
            try
            {
                if (File.Exists(tmp))
                {
                    File.Delete(tmp);
                }
            }
            catch (IOException)
            {
            }
        }
    }

    /// <summary>Creates the directory with mode 0700 on Unix.</summary>
    protected internal static void CreatePrivateDirectory(string dir)
    {
        if (Directory.Exists(dir))
        {
            return;
        }
        if (OperatingSystem.IsWindows())
        {
            Directory.CreateDirectory(dir);
        }
        else
        {
            Directory.CreateDirectory(dir, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
    }

    internal static bool IsUnix => !RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
}

/// <summary>
/// Cross-process lock held around refresh and every store write. Implementations: <see cref="NoRefreshLock"/>
/// (single process), <see cref="FileRefreshLock"/> (any OS), and the named mutex lock in MoonSso.Desktop.
/// </summary>
public interface IRefreshLock
{
    /// <summary>Acquires the lock; dispose the result to release it.</summary>
    Task<IAsyncDisposable> AcquireAsync(CancellationToken cancellationToken = default);
}

/// <summary>No cross-process locking (the store is not shared between processes).</summary>
public sealed class NoRefreshLock : IRefreshLock
{
    public static readonly NoRefreshLock Instance = new();

    public Task<IAsyncDisposable> AcquireAsync(CancellationToken cancellationToken = default) => Task.FromResult<IAsyncDisposable>(Releaser.Instance);

    private sealed class Releaser : IAsyncDisposable
    {
        public static readonly Releaser Instance = new();

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}

/// <summary>
/// Cross-process lock based on an exclusively opened lock file (<c>FileShare.None</c>, which .NET maps to <c>flock</c> on Unix).
/// </summary>
public sealed class FileRefreshLock : IRefreshLock
{
    public FileRefreshLock(string lockFilePath, TimeSpan? timeout = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(lockFilePath);
        LockFilePath = Path.GetFullPath(lockFilePath);
        Timeout = timeout ?? TimeSpan.FromMinutes(2);
    }

    public string LockFilePath { get; }

    public TimeSpan Timeout { get; }

    public async Task<IAsyncDisposable> AcquireAsync(CancellationToken cancellationToken = default)
    {
        FileTokenStore.CreatePrivateDirectory(Path.GetDirectoryName(LockFilePath)!);
        var deadline = DateTime.UtcNow + Timeout;
        var delay = 10;
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var options = new FileStreamOptions { Mode = FileMode.OpenOrCreate, Access = FileAccess.ReadWrite, Share = FileShare.None };
                if (!OperatingSystem.IsWindows())
                {
                    options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
                }
                return new Holder(new FileStream(LockFilePath, options));
            }
            catch (IOException) when (DateTime.UtcNow < deadline)
            {
                await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
                delay = Math.Min(delay * 2, 100);
            }
            catch (UnauthorizedAccessException) when (DateTime.UtcNow < deadline)
            {
                await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
                delay = Math.Min(delay * 2, 100);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                throw new MoonSsoException(ErrorCodes.LockTimeout, "Timed out waiting for the token refresh lock.", innerException: ex);
            }
        }
    }

    private sealed class Holder : IAsyncDisposable
    {
        private FileStream? _fs;

        public Holder(FileStream fs) => _fs = fs;

        public ValueTask DisposeAsync()
        {
            Interlocked.Exchange(ref _fs, null)?.Dispose();
            return ValueTask.CompletedTask;
        }
    }
}
