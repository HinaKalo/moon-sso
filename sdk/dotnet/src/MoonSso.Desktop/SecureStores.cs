using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

namespace MoonSso.Desktop;

/// <summary>
/// Windows: the session file is encrypted with DPAPI (<c>DataProtectionScope.CurrentUser</c>), so only the same Windows user can read it.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class DpapiTokenStore : FileTokenStore
{
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("moon-sso-sdk-dotnet/session/v1");

    public DpapiTokenStore(string path)
        : base(path)
    {
    }

    protected override byte[] Protect(byte[] plaintext) => ProtectedData.Protect(plaintext, Entropy, DataProtectionScope.CurrentUser);

    protected override byte[] Unprotect(byte[] data) => ProtectedData.Unprotect(data, Entropy, DataProtectionScope.CurrentUser);
}

/// <summary>A source of a 256-bit key kept in OS secure storage.</summary>
public interface ISecretKeyProvider
{
    /// <summary>Returns the stored key, creating and storing a new one when <paramref name="create"/> is true and none exists.</summary>
    /// <exception cref="SecureStorageUnavailableException">The OS secure storage cannot be used.</exception>
    Task<byte[]?> GetKeyAsync(bool create, CancellationToken cancellationToken);

    /// <summary>Deletes the key.</summary>
    Task DeleteKeyAsync(CancellationToken cancellationToken);
}

/// <summary>The OS secure storage (Keychain, Secret Service) is not available.</summary>
public sealed class SecureStorageUnavailableException : Exception
{
    public SecureStorageUnavailableException(string message, Exception? inner = null)
        : base(message, inner)
    {
    }
}

/// <summary>
/// Session file encrypted with AES-256-GCM; the key lives in OS secure storage (<see cref="ISecretKeyProvider"/>). Keeping only a short
/// key in the keychain avoids size limits and never passes secrets on a command line.
/// </summary>
public class KeyWrappedFileTokenStore : FileTokenStore
{
    private static readonly byte[] Magic = "MSS1"u8.ToArray();
    private readonly ISecretKeyProvider _keys;
    private byte[]? _key;

    public KeyWrappedFileTokenStore(string path, ISecretKeyProvider keys)
        : base(path)
    {
        _keys = keys ?? throw new ArgumentNullException(nameof(keys));
    }

    public override async Task<StoredSession?> LoadAsync(CancellationToken cancellationToken = default)
    {
        if (!File.Exists(FilePath))
        {
            return null;
        }
        _key ??= await _keys.GetKeyAsync(create: false, cancellationToken).ConfigureAwait(false);
        if (_key is null)
        {
            return null; // key lost: the file cannot be decrypted
        }
        return await base.LoadAsync(cancellationToken).ConfigureAwait(false);
    }

    public override async Task SaveAsync(StoredSession session, CancellationToken cancellationToken = default)
    {
        _key ??= await _keys.GetKeyAsync(create: true, cancellationToken).ConfigureAwait(false)
                 ?? throw new SecureStorageUnavailableException("Secure storage did not return a key.");
        await base.SaveAsync(session, cancellationToken).ConfigureAwait(false);
    }

    public override async Task ClearAsync(CancellationToken cancellationToken = default)
    {
        await base.ClearAsync(cancellationToken).ConfigureAwait(false);
        await _keys.DeleteKeyAsync(cancellationToken).ConfigureAwait(false);
        _key = null;
    }

    protected override byte[] Protect(byte[] plaintext)
    {
        var key = _key ?? throw new InvalidOperationException("Key not loaded.");
        var nonce = RandomNumberGenerator.GetBytes(12);
        var cipher = new byte[plaintext.Length];
        var tag = new byte[16];
        using (var aes = new AesGcm(key, 16))
        {
            aes.Encrypt(nonce, plaintext, cipher, tag, Magic);
        }
        var result = new byte[Magic.Length + nonce.Length + tag.Length + cipher.Length];
        Magic.CopyTo(result, 0);
        nonce.CopyTo(result, Magic.Length);
        tag.CopyTo(result, Magic.Length + nonce.Length);
        cipher.CopyTo(result, Magic.Length + nonce.Length + tag.Length);
        return result;
    }

    protected override byte[] Unprotect(byte[] data)
    {
        var key = _key ?? throw new CryptographicException("Key not loaded.");
        if (data.Length < Magic.Length + 28 || !data.AsSpan(0, Magic.Length).SequenceEqual(Magic))
        {
            throw new CryptographicException("Unknown session file format.");
        }
        var nonce = data.AsSpan(Magic.Length, 12);
        var tag = data.AsSpan(Magic.Length + 12, 16);
        var cipher = data.AsSpan(Magic.Length + 28);
        var plain = new byte[cipher.Length];
        using var aes = new AesGcm(key, 16);
        aes.Decrypt(nonce, cipher, tag, plain, Magic);
        return plain;
    }
}

/// <summary>macOS Keychain (generic password) accessed through the <c>/usr/bin/security</c> tool.</summary>
[SupportedOSPlatform("macos")]
public sealed class KeychainKeyProvider : ISecretKeyProvider
{
    private const string Security = "/usr/bin/security";
    private readonly string _service;
    private readonly string _account;

    public KeychainKeyProvider(string service, string account = "session-key")
    {
        _service = service;
        _account = account;
    }

    public async Task<byte[]?> GetKeyAsync(bool create, CancellationToken cancellationToken)
    {
        var find = await ProcessRunner.RunAsync(Security, new[] { "find-generic-password", "-s", _service, "-a", _account, "-w" }, null, cancellationToken).ConfigureAwait(false);
        if (find.ExitCode == 0 && KeyCodec.TryDecode(find.StdOut.Trim(), out var existing))
        {
            return existing;
        }
        if (find.ExitCode == -1)
        {
            throw new SecureStorageUnavailableException("The macOS security tool is not available.");
        }
        if (!create)
        {
            return null;
        }
        var key = RandomNumberGenerator.GetBytes(32);
        // "security -i" reads the command from stdin, so the key never appears in the process list.
        var command = $"add-generic-password -U -s {Quote(_service)} -a {Quote(_account)} -l {Quote(_service)} -w {Convert.ToBase64String(key)}\n";
        var add = await ProcessRunner.RunAsync(Security, new[] { "-i" }, command, cancellationToken).ConfigureAwait(false);
        if (add.ExitCode != 0)
        {
            throw new SecureStorageUnavailableException($"Could not store the key in the Keychain (exit {add.ExitCode}).");
        }
        return key;
    }

    public async Task DeleteKeyAsync(CancellationToken cancellationToken)
    {
        await ProcessRunner.RunAsync(Security, new[] { "delete-generic-password", "-s", _service, "-a", _account }, null, cancellationToken).ConfigureAwait(false);
    }

    private static string Quote(string s) => "\"" + s.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("\"", "\\\"", StringComparison.Ordinal) + "\"";
}

internal static class KeyCodec
{
    public static bool TryDecode(string s, out byte[] key)
    {
        key = Array.Empty<byte>();
        try
        {
            key = Convert.FromBase64String(s);
            return key.Length == 32;
        }
        catch (FormatException)
        {
            return false;
        }
    }
}

/// <summary>Linux Secret Service (GNOME Keyring, KWallet, ...) accessed through <c>secret-tool</c> (libsecret).</summary>
[SupportedOSPlatform("linux")]
[SupportedOSPlatform("freebsd")]
public sealed class SecretToolKeyProvider : ISecretKeyProvider
{
    private readonly string _service;
    private readonly string _account;

    public SecretToolKeyProvider(string service, string account = "session-key")
    {
        _service = service;
        _account = account;
    }

    /// <summary>True when <c>secret-tool</c> is on the PATH.</summary>
    public static bool IsInstalled => ProcessRunner.FindOnPath("secret-tool") is not null;

    public async Task<byte[]?> GetKeyAsync(bool create, CancellationToken cancellationToken)
    {
        var tool = ProcessRunner.FindOnPath("secret-tool") ?? throw new SecureStorageUnavailableException("secret-tool is not installed.");
        var lookup = await ProcessRunner.RunAsync(tool, new[] { "lookup", "service", _service, "account", _account }, null, cancellationToken).ConfigureAwait(false);
        if (lookup.ExitCode == 0 && KeyCodec.TryDecode(lookup.StdOut.Trim(), out var existing))
        {
            return existing;
        }
        if (lookup.ExitCode != 0 && lookup.StdErr.Length > 0)
        {
            // secret-tool prints nothing when the item is missing; any message means the service is unreachable (no D-Bus session, locked...).
            throw new SecureStorageUnavailableException("Secret Service is not available: " + lookup.StdErr.Trim());
        }
        if (!create)
        {
            return null;
        }
        var key = RandomNumberGenerator.GetBytes(32);
        // secret-tool store reads the secret from stdin.
        var store = await ProcessRunner.RunAsync(tool, new[] { "store", "--label", _service, "service", _service, "account", _account },
            Convert.ToBase64String(key), cancellationToken).ConfigureAwait(false);
        if (store.ExitCode != 0)
        {
            throw new SecureStorageUnavailableException("Could not store the key with secret-tool: " + store.StdErr.Trim());
        }
        return key;
    }

    public async Task DeleteKeyAsync(CancellationToken cancellationToken)
    {
        var tool = ProcessRunner.FindOnPath("secret-tool");
        if (tool is not null)
        {
            await ProcessRunner.RunAsync(tool, new[] { "clear", "service", _service, "account", _account }, null, cancellationToken).ConfigureAwait(false);
        }
    }
}

/// <summary>
/// Linux store: Secret Service through <c>secret-tool</c>; when unavailable, falls back to a file with mode 0600 and logs a warning.
/// </summary>
public sealed class LinuxTokenStore : ITokenStore
{
    private readonly KeyWrappedFileTokenStore? _secure;
    private readonly FileTokenStore _fallback;
    private readonly Action<MoonSsoLogLevel, string>? _log;
    private volatile bool _useFallback;

    public LinuxTokenStore(string directory, string service, Action<MoonSsoLogLevel, string>? logger = null)
    {
        _log = logger;
        _fallback = new FileTokenStore(Path.Combine(directory, "session.json"));
#pragma warning disable CA1416 // guarded by the OS checks
        if (!OperatingSystem.IsWindows() && !OperatingSystem.IsMacOS() && SecretToolKeyProvider.IsInstalled)
        {
            _secure = new KeyWrappedFileTokenStore(Path.Combine(directory, "session.dat"), new SecretToolKeyProvider(service));
        }
#pragma warning restore CA1416
        else
        {
            UseFallback("secret-tool (libsecret) is not installed");
        }
    }

    /// <summary>True when the insecure 0600 file fallback is in use.</summary>
    public bool IsUsingFallback => _useFallback;

    public async Task<StoredSession?> LoadAsync(CancellationToken cancellationToken = default)
    {
        if (!_useFallback && _secure is not null)
        {
            try
            {
                return await _secure.LoadAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (SecureStorageUnavailableException ex)
            {
                UseFallback(ex.Message);
            }
        }
        return await _fallback.LoadAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task SaveAsync(StoredSession session, CancellationToken cancellationToken = default)
    {
        if (!_useFallback && _secure is not null)
        {
            try
            {
                await _secure.SaveAsync(session, cancellationToken).ConfigureAwait(false);
                return;
            }
            catch (SecureStorageUnavailableException ex)
            {
                UseFallback(ex.Message);
            }
        }
        await _fallback.SaveAsync(session, cancellationToken).ConfigureAwait(false);
    }

    public async Task ClearAsync(CancellationToken cancellationToken = default)
    {
        if (_secure is not null)
        {
            try
            {
                await _secure.ClearAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (SecureStorageUnavailableException)
            {
            }
        }
        await _fallback.ClearAsync(cancellationToken).ConfigureAwait(false);
    }

    private void UseFallback(string reason)
    {
        if (_useFallback)
        {
            return;
        }
        _useFallback = true;
        var message = $"Secure storage unavailable ({reason}); storing the Moon SSO session in {_fallback.FilePath} with mode 0600. Install libsecret-tools (secret-tool) and a Secret Service provider for encrypted storage.";
        if (_log is not null)
        {
            _log(MoonSsoLogLevel.Warning, message);
        }
        else
        {
            Trace.TraceWarning(message);
        }
    }
}

/// <summary>Chooses the OS secure store for a desktop app.</summary>
public static class DesktopTokenStore
{
    /// <summary>
    /// Windows: DPAPI-encrypted file in <c>%LOCALAPPDATA%\MoonSso\&lt;appId&gt;</c>; macOS: AES-GCM file in
    /// <c>~/Library/Application Support/MoonSso/&lt;appId&gt;</c> with the key in the Keychain; Linux: the same with the key in the
    /// Secret Service (<c>$XDG_DATA_HOME/moon-sso/&lt;appId&gt;</c>), falling back to a 0600 file with a warning.
    /// </summary>
    /// <param name="appId">Stable identifier of the application, e.g. <c>com.example.notes</c> (letters, digits, '.', '-', '_').</param>
    public static ITokenStore CreateDefault(string appId, Action<MoonSsoLogLevel, string>? logger = null)
    {
        var dir = GetDataDirectory(appId);
        var service = "moon-sso." + appId;
        if (OperatingSystem.IsWindows())
        {
            return new DpapiTokenStore(Path.Combine(dir, "session.dat"));
        }
        if (OperatingSystem.IsMacOS())
        {
            return new KeyWrappedFileTokenStore(Path.Combine(dir, "session.dat"), new KeychainKeyProvider(service));
        }
        return new LinuxTokenStore(dir, service, logger);
    }

    /// <summary>Per-user data directory used for the session and the lock file.</summary>
    public static string GetDataDirectory(string appId)
    {
        ValidateAppId(appId);
        if (OperatingSystem.IsWindows())
        {
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData, Environment.SpecialFolderOption.Create), "MoonSso", appId);
        }
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (OperatingSystem.IsMacOS())
        {
            return Path.Combine(home, "Library", "Application Support", "MoonSso", appId);
        }
        var xdg = Environment.GetEnvironmentVariable("XDG_DATA_HOME");
        var root = string.IsNullOrEmpty(xdg) || !Path.IsPathRooted(xdg) ? Path.Combine(home, ".local", "share") : xdg;
        return Path.Combine(root, "moon-sso", appId);
    }

    internal static void ValidateAppId(string appId)
    {
        ArgumentException.ThrowIfNullOrEmpty(appId);
        if (appId.Length > 100 || appId.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or '_')) || appId.StartsWith('.'))
        {
            throw new ArgumentException("appId may only contain letters, digits, '.', '-' and '_'.", nameof(appId));
        }
    }
}

internal static class ProcessRunner
{
    internal readonly record struct Result(int ExitCode, string StdOut, string StdErr);

    public static string? FindOnPath(string name)
    {
        var path = Environment.GetEnvironmentVariable("PATH");
        if (string.IsNullOrEmpty(path))
        {
            return null;
        }
        foreach (var dir in path.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            var candidate = Path.Combine(dir, name);
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }
        return null;
    }

    /// <summary>Runs a tool without a shell. Returns exit code -1 when it cannot be started.</summary>
    public static async Task<Result> RunAsync(string fileName, IEnumerable<string> args, string? stdin, CancellationToken ct)
    {
        var psi = new ProcessStartInfo(fileName)
        {
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        foreach (var a in args)
        {
            psi.ArgumentList.Add(a);
        }
        Process? p;
        try
        {
            p = Process.Start(psi);
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or FileNotFoundException)
        {
            return new Result(-1, "", ex.Message);
        }
        if (p is null)
        {
            return new Result(-1, "", "process did not start");
        }
        using (p)
        {
            var stdout = p.StandardOutput.ReadToEndAsync(ct);
            var stderr = p.StandardError.ReadToEndAsync(ct);
            if (stdin is not null)
            {
                await p.StandardInput.WriteAsync(stdin.AsMemory(), ct).ConfigureAwait(false);
            }
            p.StandardInput.Close();
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(30));
            try
            {
                await p.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                try
                {
                    p.Kill(entireProcessTree: true);
                }
                catch (InvalidOperationException)
                {
                }
                ct.ThrowIfCancellationRequested();
                throw new SecureStorageUnavailableException($"{Path.GetFileName(fileName)} did not respond (is the keyring locked?).");
            }
            return new Result(p.ExitCode, await stdout.ConfigureAwait(false), await stderr.ConfigureAwait(false));
        }
    }
}
