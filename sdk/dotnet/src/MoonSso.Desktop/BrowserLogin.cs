using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace MoonSso.Desktop;

/// <summary>Options of <see cref="DesktopLoginExtensions.LoginWithBrowserAsync"/>.</summary>
public sealed record BrowserLoginOptions
{
    /// <summary>How long to wait for the user to finish in the browser (default 5 minutes).</summary>
    public TimeSpan Timeout { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>Authorization request parameters (scope, prompt, login_hint, ...).</summary>
    public AuthorizationOptions? Authorization { get; init; }

    /// <summary>Opens the URL. Defaults to <see cref="SystemBrowser.Open"/>.</summary>
    public Func<Uri, CancellationToken, Task>? OpenBrowser { get; init; }

    /// <summary>HTML shown in the browser after a successful callback.</summary>
    public string SuccessHtml { get; init; } = LoopbackCallbackListener.DefaultSuccessHtml;

    /// <summary>HTML shown when the server returned an error (<c>{0}</c> is replaced with the HTML-encoded error code).</summary>
    public string ErrorHtml { get; init; } = LoopbackCallbackListener.DefaultErrorHtml;
}

/// <summary>System-browser login for desktop apps (RFC 8252: loopback redirect on <c>http://127.0.0.1:&lt;random port&gt;/callback</c>).</summary>
public static class DesktopLoginExtensions
{
    /// <summary>
    /// Opens the system browser on the authorization page, waits for the loopback callback (5 minutes by default), validates
    /// state / iss and redeems the code. The browser tab shows "登录完成，可以关闭此页面".
    /// </summary>
    /// <exception cref="TimeoutException">The user did not finish in time.</exception>
    /// <exception cref="MoonSsoException">The server returned an error (e.g. <c>access_denied</c>) or validation failed.</exception>
    public static async Task<TokenSet> LoginWithBrowserAsync(this MoonSsoClient client, BrowserLoginOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(client);
        options ??= new BrowserLoginOptions();
        using var listener = LoopbackCallbackListener.Start(options.SuccessHtml, options.ErrorHtml);
        var request = await client.CreateAuthorizationRequestAsync(listener.RedirectUri, options.Authorization, cancellationToken).ConfigureAwait(false);
        listener.ExpectedState = request.State;
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(options.Timeout);
        var open = options.OpenBrowser ?? ((u, _) =>
        {
            SystemBrowser.Open(u);
            return Task.CompletedTask;
        });
        await open(request.Url, timeout.Token).ConfigureAwait(false);
        IReadOnlyDictionary<string, string> callback;
        try
        {
            callback = await listener.WaitForCallbackAsync(timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException("The browser login was not completed in time.");
        }
        return await client.ExchangeCodeAsync(request, callback, cancellationToken).ConfigureAwait(false);
    }
}

/// <summary>
/// One-shot loopback HTTP listener for the authorization callback. Binds <c>http://127.0.0.1:&lt;free port&gt;/</c> and accepts
/// <c>GET /callback</c>; other paths get 404 and callbacks with a foreign <c>state</c> are rejected without ending the wait.
/// </summary>
public sealed class LoopbackCallbackListener : IDisposable
{
    internal const string DefaultSuccessHtml =
        "<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">" +
        "<title>登录完成</title><style>body{font-family:system-ui,-apple-system,'Segoe UI','PingFang SC','Microsoft YaHei',sans-serif;background:#f6f7f9;color:#1f2329;" +
        "display:flex;align-items:center;justify-content:center;height:100vh;margin:0}main{background:#fff;padding:40px 48px;border-radius:12px;" +
        "box-shadow:0 2px 12px rgba(0,0,0,.08);text-align:center}h1{font-size:20px;margin:0 0 8px}p{margin:0;color:#646a73}" +
        "@media(prefers-color-scheme:dark){body{background:#17181a;color:#e8e9eb}main{background:#232427}p{color:#a3a6ad}}</style></head>" +
        "<body><main><h1>登录完成</h1><p>可以关闭此页面并返回应用。</p></main><script>setTimeout(function(){window.close()},1500)</script></body></html>";

    internal const string DefaultErrorHtml =
        "<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\"><title>登录未完成</title><style>body{font-family:system-ui,sans-serif;" +
        "display:flex;align-items:center;justify-content:center;height:100vh;margin:0}main{text-align:center}</style></head>" +
        "<body><main><h1>登录未完成</h1><p>错误：{0}</p><p>请返回应用重试。</p></main></body></html>";

    private readonly HttpListener _listener;
    private readonly string _successHtml;
    private readonly string _errorHtml;
    private int _disposed;

    private LoopbackCallbackListener(HttpListener listener, int port, string successHtml, string errorHtml)
    {
        _listener = listener;
        Port = port;
        _successHtml = successHtml;
        _errorHtml = errorHtml;
        RedirectUri = $"http://127.0.0.1:{port}/callback";
    }

    public int Port { get; }

    /// <summary><c>http://127.0.0.1:&lt;port&gt;/callback</c>.</summary>
    public string RedirectUri { get; }

    /// <summary>When set, callbacks whose <c>state</c> differs are answered with 400 and ignored.</summary>
    public string? ExpectedState { get; set; }

    /// <summary>Starts listening on a random free loopback port.</summary>
    public static LoopbackCallbackListener Start(string? successHtml = null, string? errorHtml = null)
    {
        HttpListenerException? last = null;
        for (var attempt = 0; attempt < 10; attempt++)
        {
            var port = GetFreePort();
            var listener = new HttpListener();
            listener.Prefixes.Add($"http://127.0.0.1:{port}/");
            try
            {
                listener.Start();
                return new LoopbackCallbackListener(listener, port, successHtml ?? DefaultSuccessHtml, errorHtml ?? DefaultErrorHtml);
            }
            catch (HttpListenerException ex)
            {
                last = ex;
                listener.Close();
            }
        }
        throw new InvalidOperationException("Could not start the loopback callback listener.", last);
    }

    private static int GetFreePort()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        try
        {
            return ((IPEndPoint)l.LocalEndpoint).Port;
        }
        finally
        {
            l.Stop();
        }
    }

    /// <summary>Waits for <c>GET /callback</c> and returns its query parameters after answering the browser.</summary>
    public async Task<IReadOnlyDictionary<string, string>> WaitForCallbackAsync(CancellationToken cancellationToken)
    {
        using var reg = cancellationToken.Register(() =>
        {
            try
            {
                _listener.Stop();
            }
            catch (ObjectDisposedException)
            {
            }
        });
        while (true)
        {
            HttpListenerContext ctx;
            try
            {
                ctx = await _listener.GetContextAsync().ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is HttpListenerException or ObjectDisposedException or InvalidOperationException)
            {
                cancellationToken.ThrowIfCancellationRequested();
                throw new MoonSsoException(MoonSso.ErrorCodes.Network, "The loopback listener stopped unexpectedly.", innerException: ex);
            }
            var req = ctx.Request;
            if (req.HttpMethod != "GET" || req.Url is null || req.Url.AbsolutePath.TrimEnd('/') != "/callback")
            {
                await RespondAsync(ctx, 404, "<!doctype html><title>Not found</title>").ConfigureAwait(false);
                continue;
            }
            var query = QueryString.Parse(req.Url.Query);
            query.TryGetValue("state", out var state);
            if (ExpectedState is not null && state != ExpectedState)
            {
                await RespondAsync(ctx, 400, _errorHtml.Replace("{0}", "invalid_state", StringComparison.Ordinal)).ConfigureAwait(false);
                continue;
            }
            if (query.TryGetValue("error", out var error))
            {
                await RespondAsync(ctx, 200, _errorHtml.Replace("{0}", WebUtility.HtmlEncode(error), StringComparison.Ordinal)).ConfigureAwait(false);
            }
            else
            {
                await RespondAsync(ctx, 200, _successHtml).ConfigureAwait(false);
            }
            return query;
        }
    }

    private static async Task RespondAsync(HttpListenerContext ctx, int status, string html)
    {
        try
        {
            var bytes = Encoding.UTF8.GetBytes(html);
            ctx.Response.StatusCode = status;
            ctx.Response.ContentType = "text/html; charset=utf-8";
            ctx.Response.Headers["Cache-Control"] = "no-store";
            ctx.Response.Headers["Referrer-Policy"] = "no-referrer";
            ctx.Response.Headers["Connection"] = "close";
            ctx.Response.ContentLength64 = bytes.Length;
            await ctx.Response.OutputStream.WriteAsync(bytes).ConfigureAwait(false);
            ctx.Response.Close();
        }
        catch (Exception ex) when (ex is HttpListenerException or IOException or ObjectDisposedException)
        {
            // browser went away; nothing to do
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }
        try
        {
            _listener.Close();
        }
        catch (ObjectDisposedException)
        {
        }
    }
}

/// <summary>Opens URLs in the user's default browser.</summary>
public static class SystemBrowser
{
    /// <summary>
    /// Opens <paramref name="url"/> (http/https only): <c>Process.Start</c> with <c>UseShellExecute</c> on Windows, <c>open</c> on macOS,
    /// <c>xdg-open</c> on Linux/BSD.
    /// </summary>
    public static void Open(Uri url)
    {
        ArgumentNullException.ThrowIfNull(url);
        if (!url.IsAbsoluteUri || (url.Scheme != Uri.UriSchemeHttps && url.Scheme != Uri.UriSchemeHttp))
        {
            throw new ArgumentException("Only absolute http(s) URLs can be opened.", nameof(url));
        }
        var target = url.AbsoluteUri;
        ProcessStartInfo psi;
        if (OperatingSystem.IsWindows())
        {
            psi = new ProcessStartInfo(target) { UseShellExecute = true };
        }
        else if (OperatingSystem.IsMacOS())
        {
            psi = new ProcessStartInfo("open") { UseShellExecute = false };
            psi.ArgumentList.Add(target);
        }
        else
        {
            psi = new ProcessStartInfo("xdg-open") { UseShellExecute = false };
            psi.ArgumentList.Add(target);
        }
        using var p = Process.Start(psi) ?? throw new InvalidOperationException("Could not start the system browser.");
    }
}
