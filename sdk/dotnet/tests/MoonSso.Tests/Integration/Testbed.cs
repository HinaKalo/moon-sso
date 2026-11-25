using System.Collections.Concurrent;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using MoonSso;

namespace MoonSso.Tests.Integration;

/// <summary>Helpers for the local Moon SSO testbed (docs/sdk-spec.md §8). Override the URL with MOON_SSO_TESTBED.</summary>
internal static class Testbed
{
    public static readonly string Issuer = (Environment.GetEnvironmentVariable("MOON_SSO_TESTBED") ?? "http://127.0.0.1:18601").TrimEnd('/');
    public const string AlicePassword = "Wonderland-Pass-1";
    public const string BobPassword = "Builder-Pass-22";
    public const string BobTotpSecret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
    public const string FullScope = "openid profile offline_access profile:write password:write";

    public static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(30) };

    private static readonly Lazy<Task> Reachable = new(async () =>
    {
        try
        {
            using var resp = await Http.GetAsync(Issuer + "/.well-known/openid-configuration");
            resp.EnsureSuccessStatusCode();
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Moon SSO testbed is not reachable at {Issuer}. Start server/bin/testbed.exe.", ex);
        }
    });

    public static Task EnsureReachableAsync() => Reachable.Value;

    public static MoonSsoClient CreateClient(string clientId = "test-native", Action<MoonSsoOptions>? configure = null)
    {
        var o = new MoonSsoOptions { Issuer = Issuer, ClientId = clientId, Scope = FullScope, TokenStore = new InMemoryTokenStore() };
        configure?.Invoke(o);
        return new MoonSsoClient(o);
    }

    public static string RandomUsername()
    {
        const string chars = "abcdefghijklmnopqrstuvwxyz0123456789";
        return "t_" + new string(Enumerable.Range(0, 8).Select(_ => chars[RandomNumberGenerator.GetInt32(chars.Length)]).ToArray());
    }

    public static string RandomPassword() => "Pw-" + Convert.ToBase64String(RandomNumberGenerator.GetBytes(12)).Replace('/', 'x').Replace('+', 'y') + "!9";

    /// <summary>Creates a fresh user via <c>POST /__test/users</c>.</summary>
    public static async Task<(string Username, string Password)> CreateUserAsync()
    {
        await EnsureReachableAsync();
        var username = RandomUsername();
        var password = RandomPassword();
        using var resp = await Http.PostAsJsonAsync(Issuer + "/__test/users", new { username, password });
        var body = await resp.Content.ReadAsStringAsync();
        Assert.True(resp.IsSuccessStatusCode, $"create user failed: {(int)resp.StatusCode} {body}");
        return (username, password);
    }

    public static async Task<string> TotpAsync(string secret)
    {
        using var resp = await Http.PostAsync(Issuer + "/__test/totp?secret=" + Uri.EscapeDataString(secret), null);
        resp.EnsureSuccessStatusCode();
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        return doc.RootElement.GetProperty("code").GetString()!;
    }

    /// <summary><c>POST /__test/authorize</c>: completes the browser step and returns the callback redirect URL.</summary>
    public static async Task<Uri> AuthorizeAsync(Uri authorizationUrl, string username, string password)
    {
        var form = QueryString.Parse(authorizationUrl.Query).ToDictionary(kv => kv.Key, kv => kv.Value);
        form["username"] = username;
        form["password"] = password;
        using var resp = await Http.PostAsync(Issuer + "/__test/authorize", new FormUrlEncodedContent(form));
        var body = await resp.Content.ReadAsStringAsync();
        Assert.True(resp.IsSuccessStatusCode, $"__test/authorize failed: {(int)resp.StatusCode} {body}");
        using var doc = JsonDocument.Parse(body);
        return new Uri(doc.RootElement.GetProperty("redirect").GetString()!);
    }

    public static async Task SetDisplayNameAsync(string username, string displayName)
    {
        using var resp = await Http.PostAsJsonAsync(Issuer + "/__test/users/" + Uri.EscapeDataString(username) + "/profile", new { display_name = displayName });
        resp.EnsureSuccessStatusCode();
    }

    public static async Task<string> InitialAccessTokenAsync()
    {
        using var resp = await Http.PostAsync(Issuer + "/__test/iat", null);
        resp.EnsureSuccessStatusCode();
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        return doc.RootElement.GetProperty("token").GetString()!;
    }

    /// <summary>Retries an operation that may be throttled (<c>slow_down</c>) by other suites sharing the testbed.</summary>
    public static async Task<T> WithThrottleRetryAsync<T>(Func<Task<T>> op)
    {
        for (var attempt = 0; ; attempt++)
        {
            try
            {
                return await op();
            }
            catch (MoonSsoException ex) when (ex.Error == "slow_down" && attempt < 5)
            {
                await Task.Delay(TimeSpan.FromSeconds(2 + attempt * 2));
            }
        }
    }
}

/// <summary>Records every HTTP exchange (method, path, status, OAuth error) passing through the SDK.</summary>
internal sealed class RecordingHandler : DelegatingHandler
{
    public RecordingHandler()
        : base(new SocketsHttpHandler { AllowAutoRedirect = false })
    {
    }

    public ConcurrentQueue<(string Method, string Path, int Status, string? Error, bool HasDPoP)> Log { get; } = new();

    public int Count(string path, string method = "POST") => Log.Count(e => e.Path == path && e.Method == method);

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var resp = await base.SendAsync(request, cancellationToken);
        string? error = null;
        if ((int)resp.StatusCode >= 400 && resp.Content.Headers.ContentType?.MediaType == "application/json")
        {
            await resp.Content.LoadIntoBufferAsync();
            try
            {
                using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(cancellationToken));
                error = doc.RootElement.TryGetProperty("error", out var e) ? e.GetString() : null;
            }
            catch (JsonException)
            {
            }
        }
        Log.Enqueue((request.Method.Method, request.RequestUri!.AbsolutePath, (int)resp.StatusCode, error, request.Headers.Contains("DPoP")));
        return resp;
    }
}
