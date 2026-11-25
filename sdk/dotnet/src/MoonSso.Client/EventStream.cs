using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using MoonSso.Internal;

namespace MoonSso;

/// <summary>One dispatched Server-Sent Event.</summary>
public sealed record SseEvent(string? Id, string Event, string Data);

/// <summary>
/// Incremental Server-Sent Events parser (WHATWG HTML §9.2): handles <c>id:</c>, <c>event:</c>, <c>data:</c> (multi-line),
/// <c>retry:</c> and comment lines. Feed it one line at a time without the line terminator.
/// </summary>
public sealed class SseParser
{
    private readonly StringBuilder _data = new();
    private string? _eventType;
    private bool _hasData;

    /// <summary>The last event id seen (persists across events, as the spec requires).</summary>
    public string? LastEventId { get; private set; }

    /// <summary>Reconnection delay requested with <c>retry:</c>, if any.</summary>
    public int? RetryMilliseconds { get; private set; }

    /// <summary>Processes one line. Returns an event when the line completes one (blank line), otherwise null.</summary>
    public SseEvent? ProcessLine(string line)
    {
        ArgumentNullException.ThrowIfNull(line);
        if (line.Length == 0)
        {
            return Dispatch();
        }
        if (line[0] == ':')
        {
            return null; // comment (e.g. ": ping")
        }
        string field, value;
        var colon = line.IndexOf(':');
        if (colon < 0)
        {
            field = line;
            value = "";
        }
        else
        {
            field = line[..colon];
            value = line[(colon + 1)..];
            if (value.Length > 0 && value[0] == ' ')
            {
                value = value[1..];
            }
        }
        switch (field)
        {
            case "event":
                _eventType = value;
                break;
            case "data":
                if (_hasData)
                {
                    _data.Append('\n');
                }
                _data.Append(value);
                _hasData = true;
                break;
            case "id":
                if (!value.Contains('\0'))
                {
                    LastEventId = value;
                }
                break;
            case "retry":
                if (value.Length > 0 && value.All(char.IsAsciiDigit) && int.TryParse(value, out var ms))
                {
                    RetryMilliseconds = ms;
                }
                break;
        }
        return null;
    }

    /// <summary>Discards a partially received event (call when the connection drops).</summary>
    public void Reset()
    {
        _data.Clear();
        _hasData = false;
        _eventType = null;
    }

    private SseEvent? Dispatch()
    {
        if (!_hasData)
        {
            _eventType = null;
            return null;
        }
        var evt = new SseEvent(LastEventId, string.IsNullOrEmpty(_eventType) ? "message" : _eventType, _data.ToString());
        Reset();
        return evt;
    }
}

/// <summary>
/// Live profile events over <c>GET /api/v1/me/events</c> using streaming HTTP (bearer header, never a token in the URL), with
/// <c>Last-Event-ID</c> resume and jittered reconnect backoff. Token expiry, sign-out and profile changes are handled as the SDK spec requires.
/// </summary>
public sealed class MoonSsoEventStream : IAsyncDisposable
{
    private static readonly TimeSpan IdleTimeout = TimeSpan.FromSeconds(75); // server pings every 25 s
    private static readonly TimeSpan MaxBackoff = TimeSpan.FromSeconds(60);

    private readonly MoonSsoClient _client;
    private readonly HttpClient _http;
    private readonly object _sync = new();
    private CancellationTokenSource? _cts;
    private Task? _loop;

    internal MoonSsoEventStream(MoonSsoClient client, HttpClient http)
    {
        _client = client;
        _http = http;
    }

    /// <summary>Id of the last received event, sent as <c>Last-Event-ID</c> when reconnecting. Persist it to resume across restarts.</summary>
    public string? LastEventId { get; set; }

    /// <summary>True while the background loop runs.</summary>
    public bool IsRunning
    {
        get
        {
            lock (_sync)
            {
                return _loop is { IsCompleted: false };
            }
        }
    }

    /// <summary>A stream was opened and the server started sending (subscription active).</summary>
    public event EventHandler? Connected;

    /// <summary>Every event received (after the SDK handled it).</summary>
    public event EventHandler<ProfileEventArgs>? EventReceived;

    /// <summary>The connection failed or ended; <see cref="EventStreamErrorEventArgs.RetryIn"/> is null when the stream stopped for good.</summary>
    public event EventHandler<EventStreamErrorEventArgs>? Disconnected;

    /// <summary>Starts the background loop (no-op when already running).</summary>
    public void Start()
    {
        lock (_sync)
        {
            if (_loop is { IsCompleted: false })
            {
                return;
            }
            _cts?.Dispose();
            _cts = new CancellationTokenSource();
            var token = _cts.Token;
            _loop = Task.Run(() => RunAsync(token), CancellationToken.None);
        }
    }

    /// <summary>Stops the background loop and waits for it to finish.</summary>
    public async Task StopAsync()
    {
        Task? loop;
        lock (_sync)
        {
            _cts?.Cancel();
            loop = _loop;
        }
        if (loop is not null)
        {
            try
            {
                await loop.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
        }
    }

    /// <summary>
    /// Runs the event loop until <paramref name="cancellationToken"/> is cancelled, the session expires, or the server refuses the stream (403).
    /// </summary>
    public async Task RunAsync(CancellationToken cancellationToken)
    {
        var log = _client.Log;
        var failures = 0;
        while (!cancellationToken.IsCancellationRequested)
        {
            int? retryMs = null;
            var reconnectNow = false;
            Exception? error = null;
            try
            {
                var outcome = await ConnectOnceAsync(cancellationToken).ConfigureAwait(false);
                retryMs = outcome.RetryMs;
                switch (outcome.Kind)
                {
                    case OutcomeKind.Stop:
                        RaiseDisconnected(new MoonSsoException(outcome.Error ?? "stream_closed", outcome.Description, outcome.Status), null);
                        return;
                    case OutcomeKind.ReconnectNow:
                        failures = outcome.ReceivedData ? 0 : failures + 1;
                        reconnectNow = failures <= 2;
                        break;
                    case OutcomeKind.Ended:
                        failures = outcome.ReceivedData ? 0 : failures + 1;
                        break;
                    case OutcomeKind.Failed:
                        failures++;
                        error = new MoonSsoException(outcome.Error ?? ErrorCodes.Network, outcome.Description, outcome.Status);
                        break;
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return;
            }
            catch (SessionExpiredException ex)
            {
                RaiseDisconnected(ex, null);
                return;
            }
            catch (NotSignedInException ex)
            {
                RaiseDisconnected(ex, null);
                return;
            }
            catch (Exception ex)
            {
                failures++;
                error = ex;
                log.Warning($"Event stream error: {(ex as MoonSsoException)?.Error ?? ex.GetType().Name}.");
            }

            if (reconnectNow)
            {
                continue;
            }
            var delay = Backoff(retryMs, failures);
            if (error is not null)
            {
                RaiseDisconnected(error, delay);
            }
            try
            {
                await Task.Delay(delay, _client.Options.TimeProvider, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }

    /// <summary>Delay before reconnecting: server <c>retry</c> (or 3–8 s), doubled per consecutive failure up to 60 s, plus up to 1 s of jitter.</summary>
    internal static TimeSpan Backoff(int? retryMs, int failures)
    {
        var baseMs = retryMs is > 0 ? retryMs.Value : Random.Shared.Next(3000, 8001);
        var factor = Math.Pow(2, Math.Clamp(failures - 1, 0, 5));
        var ms = Math.Min(baseMs * factor, MaxBackoff.TotalMilliseconds);
        return TimeSpan.FromMilliseconds(ms + Random.Shared.Next(0, 1000));
    }

    private enum OutcomeKind
    {
        Ended,
        ReconnectNow,
        Failed,
        Stop,
    }

    private readonly record struct Outcome(OutcomeKind Kind, int? RetryMs = null, bool ReceivedData = false, string? Error = null, string? Description = null, int? Status = null);

    private async Task<Outcome> ConnectOnceAsync(CancellationToken ct)
    {
        var doc = await _client.Discovery.GetAsync(ct).ConfigureAwait(false);
        var url = doc.EventsEndpoint ?? doc.ApiBase + "/me/events";
        var token = await _client.Tokens.GetAccessTokenAsync(ct).ConfigureAwait(false);

        using var req = new HttpRequestMessage(HttpMethod.Get, url);
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/event-stream"));
        req.Headers.CacheControl = new CacheControlHeaderValue { NoCache = true };
        if (!string.IsNullOrEmpty(LastEventId))
        {
            req.Headers.TryAddWithoutValidation("Last-Event-ID", LastEventId);
        }

        HttpResponseMessage resp;
        using (var connectTimeout = CancellationTokenSource.CreateLinkedTokenSource(ct))
        {
            connectTimeout.CancelAfter(_client.Options.HttpTimeout);
            try
            {
                resp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, connectTimeout.Token).ConfigureAwait(false);
            }
            catch (Exception ex) when (OAuthTransport.IsNetworkFailure(ex, ct))
            {
                return new Outcome(OutcomeKind.Failed, Error: ErrorCodes.Network, Description: ex.Message);
            }
        }

        using (resp)
        {
            if (resp.StatusCode == HttpStatusCode.Unauthorized)
            {
                _client.Log.Debug("Event stream: access token rejected; refreshing.");
                await _client.Tokens.RefreshAfterRejectionAsync(token, ct).ConfigureAwait(false);
                return new Outcome(OutcomeKind.ReconnectNow);
            }
            if (resp.StatusCode == HttpStatusCode.Forbidden)
            {
                var body = await OAuthTransport.ReadJsonAsync(resp, ct).ConfigureAwait(false);
                return new Outcome(OutcomeKind.Stop, Error: body.GetString("error") ?? "insufficient_scope", Description: body.GetString("error_description"), Status: 403);
            }
            if (!resp.IsSuccessStatusCode)
            {
                return new Outcome(OutcomeKind.Failed, Error: (int)resp.StatusCode >= 500 ? "server_error" : ErrorCodes.InvalidResponse,
                    Description: "Event stream request failed.", Status: (int)resp.StatusCode);
            }
            var mediaType = resp.Content.Headers.ContentType?.MediaType;
            if (mediaType is not null && !mediaType.Equals("text/event-stream", StringComparison.OrdinalIgnoreCase))
            {
                return new Outcome(OutcomeKind.Failed, Error: ErrorCodes.InvalidResponse, Description: "Unexpected content type for the event stream.", Status: (int)resp.StatusCode);
            }

            var parser = new SseParser();
            var receivedData = false;
            var connectedRaised = false;
            var tokenExpired = false;
            await using var stream = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
            using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: false);
            using var idle = CancellationTokenSource.CreateLinkedTokenSource(ct);
            while (true)
            {
                idle.CancelAfter(IdleTimeout);
                string? line;
                try
                {
                    line = await reader.ReadLineAsync(idle.Token).ConfigureAwait(false);
                }
                catch (Exception ex) when (OAuthTransport.IsNetworkFailure(ex, ct))
                {
                    _client.Log.Debug($"Event stream interrupted ({ex.GetType().Name}).");
                    return new Outcome(OutcomeKind.Failed, parser.RetryMilliseconds, receivedData, ErrorCodes.Network, "Event stream interrupted.");
                }
                if (line is null)
                {
                    break; // server closed the stream
                }
                if (!connectedRaised)
                {
                    connectedRaised = true;
                    _client.Dispatcher.Raise(() => Connected?.Invoke(this, EventArgs.Empty));
                }
                var evt = parser.ProcessLine(line);
                if (evt is null)
                {
                    continue;
                }
                receivedData = true;
                if (evt.Id is not null)
                {
                    LastEventId = evt.Id;
                }
                var action = await HandleAsync(evt, ct).ConfigureAwait(false);
                if (action == HandleResult.TokenExpired)
                {
                    tokenExpired = true;
                }
                else if (action == HandleResult.Stop)
                {
                    return new Outcome(OutcomeKind.Stop, Error: ErrorCodes.InvalidGrant, Description: "Session ended.");
                }
            }

            if (tokenExpired)
            {
                // The stream ends when the access token expires: refresh (if not done yet) and reconnect at once.
                await _client.Tokens.RefreshAfterRejectionAsync(token, ct).ConfigureAwait(false);
                return new Outcome(OutcomeKind.ReconnectNow, parser.RetryMilliseconds, ReceivedData: true);
            }
            return new Outcome(OutcomeKind.Ended, parser.RetryMilliseconds, receivedData);
        }
    }

    private enum HandleResult
    {
        Continue,
        TokenExpired,
        Stop,
    }

    private async Task<HandleResult> HandleAsync(SseEvent sse, CancellationToken ct)
    {
        var result = HandleResult.Continue;
        ProfileEvent evt;
        try
        {
            evt = sse.Data.Length > 0 && sse.Data != "{}"
                ? (JsonSerializer.Deserialize<ProfileEvent>(sse.Data, Json.Options) ?? new ProfileEvent())
                : new ProfileEvent();
        }
        catch (JsonException)
        {
            _client.Log.Warning($"Ignoring malformed '{sse.Event}' event.");
            return result;
        }
        if (string.IsNullOrEmpty(evt.Type))
        {
            evt = evt with { Type = sse.Event };
        }

        switch (sse.Event)
        {
            case EventTypes.UserUpdated:
                await ApplyUpdateAsync(evt, ct).ConfigureAwait(false);
                break;
            case EventTypes.UserPasswordChanged:
            case EventTypes.UserDisabled:
            case EventTypes.UserDeleted:
            case EventTypes.ConsentRevoked:
                // Refresh once: invalid_grant ends the session (SessionExpired is raised); success means this device is still signed in.
                try
                {
                    await _client.Tokens.RefreshAsync(ct).ConfigureAwait(false);
                }
                catch (SessionExpiredException)
                {
                    result = HandleResult.Stop;
                }
                catch (MoonSsoException ex) when (ex.IsTransient)
                {
                    _client.Log.Warning($"Could not verify the session after '{sse.Event}' ({ex.Error}); will retry on reconnect.");
                }
                break;
            case EventTypes.Resync:
                await _client.GetMeCoreAsync("resync", ct).ConfigureAwait(false);
                break;
            case EventTypes.TokenExpired:
                result = HandleResult.TokenExpired;
                break;
        }
        _client.Dispatcher.Raise(() => EventReceived?.Invoke(this, new ProfileEventArgs(evt)));
        return result;
    }

    private async Task ApplyUpdateAsync(ProfileEvent evt, CancellationToken ct)
    {
        var data = evt.Data;
        var cached = _client.CurrentProfile;
        if (data is null || string.IsNullOrEmpty(data.Sub))
        {
            await _client.GetMeCoreAsync("event", ct).ConfigureAwait(false);
            return;
        }
        if (cached is not null && cached.Sub == data.Sub && data.ProfileVersion <= cached.ProfileVersion)
        {
            return; // stale or duplicate
        }
        var profile = new UserProfile
        {
            Sub = data.Sub,
            PreferredUsername = data.PreferredUsername,
            Name = data.Name,
            Nickname = data.Nickname,
            Picture = data.Picture,
            UpdatedAt = data.UpdatedAt,
            ProfileVersion = data.ProfileVersion,
            TotpEnabled = cached?.Sub == data.Sub ? cached.TotpEnabled : null,
        };
        await _client.ApplyProfileAsync(profile, null, "event", ct).ConfigureAwait(false);
    }

    private void RaiseDisconnected(Exception error, TimeSpan? retryIn) =>
        _client.Dispatcher.Raise(() => Disconnected?.Invoke(this, new EventStreamErrorEventArgs(error, retryIn)));

    public async ValueTask DisposeAsync()
    {
        await StopAsync().ConfigureAwait(false);
        lock (_sync)
        {
            _cts?.Dispose();
            _cts = null;
        }
        _http.Dispose();
    }
}
