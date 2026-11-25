using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace MoonSso.Internal;

/// <summary>A parsed OAuth endpoint response.</summary>
internal readonly record struct OAuthResponse(int Status, JsonElement Body)
{
    public bool IsSuccess => Status is >= 200 and < 300;

    public string? Error => Body.GetString("error");

    public MoonSsoException ToException()
    {
        var error = Error;
        var description = Body.GetString("error_description");
        if (error is null)
        {
            error = Status >= 500 ? "server_error" : ErrorCodes.InvalidResponse;
            description ??= "Unexpected HTTP status from the server.";
        }
        return new MoonSsoException(error, description, Status, Body.GetString("field"));
    }
}

/// <summary>
/// Sends form posts to OAuth endpoints with client authentication, DPoP proofs, <c>use_dpop_nonce</c> handling and
/// (optionally) one retry on network errors / 502 / 503 / 504.
/// </summary>
internal sealed class OAuthTransport
{
    private readonly HttpClient _http;
    private readonly MoonSsoOptions _options;
    private readonly DPoPNonceCache _nonces;
    private readonly Logger _log;

    public OAuthTransport(HttpClient http, MoonSsoOptions options, DPoPNonceCache nonces, Logger log)
    {
        _http = http;
        _options = options;
        _nonces = nonces;
        _log = log;
    }

    /// <param name="url">Endpoint URL.</param>
    /// <param name="form">Form fields (client_id is added for public clients).</param>
    /// <param name="dpop">Key for DPoP proofs, or null.</param>
    /// <param name="retryTransient">Retry once on network errors and 502/503/504 (token endpoint only: it is idempotent thanks to the grace window).</param>
    /// <param name="htu">DPoP htu override (defaults to <paramref name="url"/>).</param>
    public async Task<OAuthResponse> PostFormAsync(string url, IReadOnlyList<KeyValuePair<string, string>> form, DPoPKey? dpop, bool retryTransient, string? htu, CancellationToken ct)
    {
        var uri = new Uri(url);
        var networkRetries = retryTransient ? 1 : 0;
        var nonceRetries = 1;
        while (true)
        {
            using var req = new HttpRequestMessage(HttpMethod.Post, uri);
            var fields = new List<KeyValuePair<string, string>>(form);
            if (string.IsNullOrEmpty(_options.ClientSecret))
            {
                if (!fields.Any(f => f.Key == "client_id"))
                {
                    fields.Add(new("client_id", _options.ClientId));
                }
            }
            else
            {
                // client_secret_basic (RFC 6749 §2.3.1: form-urlencode id and secret first)
                var raw = Uri.EscapeDataString(_options.ClientId) + ":" + Uri.EscapeDataString(_options.ClientSecret);
                req.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(raw)));
            }
            req.Content = new FormUrlEncodedContent(fields);
            req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            if (dpop is not null)
            {
                req.Headers.TryAddWithoutValidation("DPoP", dpop.CreateProof("POST", htu ?? url, _nonces.Get(uri), _options.TimeProvider.GetUtcNow()));
            }

            HttpResponseMessage resp;
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(_options.HttpTimeout);
            try
            {
                resp = await _http.SendAsync(req, HttpCompletionOption.ResponseContentRead, timeout.Token).ConfigureAwait(false);
            }
            catch (Exception ex) when (IsNetworkFailure(ex, ct))
            {
                if (networkRetries-- > 0)
                {
                    _log.Warning($"POST {uri.AbsolutePath} failed ({ex.GetType().Name}); retrying once.");
                    await Task.Delay(RetryDelay(null), ct).ConfigureAwait(false);
                    continue;
                }
                throw new MoonSsoException(ErrorCodes.Network, $"Request to {uri.AbsolutePath} failed: {ex.Message}", innerException: ex);
            }

            using (resp)
            {
                _nonces.Update(uri, resp);
                var status = (int)resp.StatusCode;
                if (status is 502 or 503 or 504 && networkRetries-- > 0)
                {
                    _log.Warning($"POST {uri.AbsolutePath} returned {status}; retrying once.");
                    await Task.Delay(RetryDelay(resp.Headers.RetryAfter), ct).ConfigureAwait(false);
                    continue;
                }
                var body = await ReadJsonAsync(resp, ct).ConfigureAwait(false);
                var result = new OAuthResponse(status, body);
                if (!result.IsSuccess && result.Error == ErrorCodes.UseDPoPNonce && dpop is not null && nonceRetries-- > 0)
                {
                    _log.Debug($"POST {uri.AbsolutePath}: server requested a DPoP nonce; retrying with it.");
                    continue;
                }
                return result;
            }
        }
    }

    internal static bool IsNetworkFailure(Exception ex, CancellationToken callerToken) =>
        ex is HttpRequestException or IOException || (ex is OperationCanceledException && !callerToken.IsCancellationRequested);

    private static TimeSpan RetryDelay(RetryConditionHeaderValue? retryAfter)
    {
        if (retryAfter?.Delta is { } d && d > TimeSpan.Zero && d <= TimeSpan.FromSeconds(5))
        {
            return d;
        }
        return TimeSpan.FromMilliseconds(250 + Random.Shared.Next(250));
    }

    internal static async Task<JsonElement> ReadJsonAsync(HttpResponseMessage resp, CancellationToken ct)
    {
        if (resp.StatusCode == HttpStatusCode.NoContent || resp.Content is null)
        {
            return default;
        }
        var bytes = await resp.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
        if (bytes.Length == 0)
        {
            return default;
        }
        try
        {
            using var doc = JsonDocument.Parse(bytes);
            return doc.RootElement.Clone();
        }
        catch (JsonException)
        {
            return default;
        }
    }
}

/// <summary>Thin wrapper over the optional log callback.</summary>
internal sealed class Logger
{
    private readonly Action<MoonSsoLogLevel, string>? _sink;

    public Logger(Action<MoonSsoLogLevel, string>? sink) => _sink = sink;

    public void Debug(string m) => Write(MoonSsoLogLevel.Debug, m);
    public void Info(string m) => Write(MoonSsoLogLevel.Information, m);
    public void Warning(string m) => Write(MoonSsoLogLevel.Warning, m);
    public void Error(string m) => Write(MoonSsoLogLevel.Error, m);

    private void Write(MoonSsoLogLevel level, string message)
    {
        if (_sink is null)
        {
            return;
        }
        try
        {
            _sink(level, message);
        }
        catch
        {
            // a broken logger must never break authentication
        }
    }
}
