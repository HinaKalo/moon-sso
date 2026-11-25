using MoonSso.Internal;

namespace MoonSso;

/// <summary>
/// Owns the session tokens: loads and persists them, refreshes proactively (after <see cref="MoonSsoOptions.RefreshThreshold"/> of the
/// lifetime, from a background timer and before every call), and guarantees that at most one refresh runs at a time — inside the process
/// (SemaphoreSlim single-flight) and across processes sharing the store (<see cref="IRefreshLock"/>, with a store re-read after acquiring it).
/// </summary>
public sealed class TokenManager : IAsyncDisposable
{
    private static readonly TimeSpan RetryAfterFailure = TimeSpan.FromSeconds(30);

    private readonly MoonSsoOptions _options;
    private readonly ITokenStore _store;
    private readonly IRefreshLock _lock;
    private readonly Func<TokenSet, DPoPKey?, CancellationToken, Task<(TokenSet Tokens, UserProfile? Profile)>> _refresher;
    private readonly Logger _log;
    private readonly EventDispatcher _events;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly SemaphoreSlim _loadGate = new(1, 1);
    private readonly object _timerSync = new();
    private volatile StoredSession _session = new();
    private DPoPKey? _dpopKey;
    private string? _storeFingerprint;
    private volatile bool _loaded;
    private ITimer? _timer;
    private bool _disposed;

    internal TokenManager(
        MoonSsoOptions options,
        ITokenStore store,
        IRefreshLock refreshLock,
        Func<TokenSet, DPoPKey?, CancellationToken, Task<(TokenSet Tokens, UserProfile? Profile)>> refresher,
        Logger log,
        EventDispatcher events)
    {
        _options = options;
        _store = store;
        _lock = refreshLock;
        _refresher = refresher;
        _log = log;
        _events = events;
    }

    /// <summary>Raised after tokens were obtained, refreshed, adopted from another process, or removed (null).</summary>
    public event EventHandler<TokensChangedEventArgs>? TokensChanged;

    /// <summary>Raised when the session ended: refresh returned <c>invalid_grant</c>, or another process sharing the store signed out.</summary>
    public event EventHandler<SessionExpiredEventArgs>? SessionExpired;

    /// <summary>Profile carried by a refreshed ID token was newer than the cached one.</summary>
    internal event Action<UserProfile>? ProfileFromTokens;

    /// <summary>Current tokens (null when signed out). Prefer <see cref="GetAccessTokenAsync"/>, which refreshes when needed.</summary>
    public TokenSet? Current => _session.Tokens;

    /// <summary>Cached profile stored with the session.</summary>
    public UserProfile? Profile => _session.Profile;

    internal string? ProfileETag => _session.ProfileETag;

    public bool IsSignedIn => _session.Tokens is not null;

    private DateTimeOffset Now => _options.TimeProvider.GetUtcNow();

    /// <summary>Loads the persisted session once. Returns true when a session is available.</summary>
    public async Task<bool> LoadAsync(CancellationToken cancellationToken = default)
    {
        if (_loaded)
        {
            return IsSignedIn;
        }
        await _loadGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_loaded)
            {
                return IsSignedIn;
            }
            var stored = await _store.LoadAsync(cancellationToken).ConfigureAwait(false);
            await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                if (stored is not null)
                {
                    _session = stored;
                    _dpopKey = ImportKey(stored.DPoPKey);
                }
                _storeFingerprint = Fingerprint(stored?.Tokens);
                _loaded = true;
            }
            finally
            {
                _gate.Release();
            }
            ScheduleTimer();
            return IsSignedIn;
        }
        finally
        {
            _loadGate.Release();
        }
    }

    /// <summary>
    /// Returns a usable access token, refreshing first when the refresh threshold has been reached.
    /// Transient refresh failures (network, 5xx, 429) fall back to the current token while it is still valid.
    /// </summary>
    /// <exception cref="NotSignedInException">No session.</exception>
    /// <exception cref="SessionExpiredException">The refresh token was rejected.</exception>
    public async Task<string> GetAccessTokenAsync(CancellationToken cancellationToken = default)
    {
        await LoadAsync(cancellationToken).ConfigureAwait(false);
        var t = _session.Tokens ?? throw new NotSignedInException();
        if (!NeedsRefresh(t))
        {
            return t.AccessToken;
        }
        try
        {
            return (await RefreshCoreAsync(t.AccessToken, force: false, cancellationToken).ConfigureAwait(false)).AccessToken;
        }
        catch (MoonSsoException ex) when (ex.IsTransient && !IsExpired(t))
        {
            _log.Warning($"Token refresh failed transiently ({ex.Error}); using the current access token until it expires.");
            return t.AccessToken;
        }
    }

    /// <summary>
    /// Refreshes now. Concurrent callers share one refresh: a caller that waited while another refresh completed gets that result.
    /// </summary>
    public async Task<TokenSet> RefreshAsync(CancellationToken cancellationToken = default)
    {
        await LoadAsync(cancellationToken).ConfigureAwait(false);
        var t = _session.Tokens ?? throw new NotSignedInException();
        return await RefreshCoreAsync(t.AccessToken, force: true, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Forces a refresh because <paramref name="rejectedAccessToken"/> was rejected (HTTP 401). If the current token already differs
    /// (refreshed meanwhile, here or in another process), it is returned without another refresh.
    /// </summary>
    public async Task<TokenSet> RefreshAfterRejectionAsync(string rejectedAccessToken, CancellationToken cancellationToken = default)
    {
        await LoadAsync(cancellationToken).ConfigureAwait(false);
        return await RefreshCoreAsync(rejectedAccessToken, force: true, cancellationToken).ConfigureAwait(false);
    }

    private async Task<TokenSet> RefreshCoreAsync(string? staleAccessToken, bool force, CancellationToken ct)
    {
        var pending = new List<Action>();
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var cur = _session.Tokens ?? throw new NotSignedInException();
            if (staleAccessToken is not null && cur.AccessToken != staleAccessToken && !NeedsRefresh(cur))
            {
                return cur; // refreshed by another caller while we waited
            }
            if (!force && !NeedsRefresh(cur))
            {
                return cur;
            }

            await using (await AcquireLockAsync(ct).ConfigureAwait(false))
            {
                var adopted = await SyncFromStoreLockedAsync(pending, ct).ConfigureAwait(false);
                cur = _session.Tokens;
                if (cur is null)
                {
                    throw new SessionExpiredException("The session was ended by another process.");
                }
                if (adopted && !NeedsRefresh(cur) && (staleAccessToken is null || cur.AccessToken != staleAccessToken))
                {
                    _log.Debug("Adopted tokens refreshed by another process.");
                    return cur;
                }
                if (cur.RefreshToken is null)
                {
                    if (!IsExpired(cur) && !force)
                    {
                        return cur;
                    }
                    await ExpireLockedAsync("No refresh token is available.", pending).ConfigureAwait(false);
                    throw new SessionExpiredException("No refresh token is available.");
                }

                TokenSet next;
                UserProfile? fromToken;
                var key = _options.DPoPEnabled ? EnsureKeyLocked() : null;
                try
                {
                    (next, fromToken) = await _refresher(cur, key, ct).ConfigureAwait(false);
                }
                catch (SessionExpiredException ex)
                {
                    await ExpireLockedAsync(ex.ErrorDescription ?? "invalid_grant", pending).ConfigureAwait(false);
                    throw;
                }

                var merged = next with
                {
                    RefreshToken = next.RefreshToken ?? cur.RefreshToken,
                    IdToken = next.IdToken ?? cur.IdToken,
                };
                var profile = MergeProfile(_session.Profile, fromToken);
                var profileChanged = profile is not null && !ReferenceEquals(profile, _session.Profile);
                _session = _session with { Tokens = merged, Profile = profile, DPoPKey = key?.Export() ?? _session.DPoPKey };
                await PersistLockedAsync().ConfigureAwait(false);
                _log.Debug("Tokens refreshed.");
                pending.Add(() => _events.Raise(() => TokensChanged?.Invoke(this, new TokensChangedEventArgs(merged))));
                if (profileChanged)
                {
                    pending.Add(() => ProfileFromTokens?.Invoke(profile!));
                }
                return merged;
            }
        }
        finally
        {
            _gate.Release();
            ScheduleTimer();
            foreach (var a in pending)
            {
                a();
            }
        }
    }

    /// <summary>Stores tokens of a new login (replacing any session in the shared store).</summary>
    internal async Task SetSessionAsync(TokenSet tokens, UserProfile? profile, DPoPKey? key, CancellationToken ct)
    {
        await LoadAsync(ct).ConfigureAwait(false);
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await using (await AcquireLockAsync(ct).ConfigureAwait(false))
            {
                if (key is not null)
                {
                    _dpopKey = key;
                }
                _session = new StoredSession { Tokens = tokens, Profile = profile, DPoPKey = _dpopKey?.Export() ?? _session.DPoPKey };
                await PersistLockedAsync(throwOnFailure: true).ConfigureAwait(false);
            }
        }
        finally
        {
            _gate.Release();
        }
        ScheduleTimer();
        _events.Raise(() => TokensChanged?.Invoke(this, new TokensChangedEventArgs(tokens)));
    }

    /// <summary>Updates the cached profile (and its ETag) in memory and in the store.</summary>
    internal async Task SetProfileAsync(UserProfile profile, string? etag, CancellationToken ct)
    {
        var pending = new List<Action>();
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await using (await AcquireLockAsync(ct).ConfigureAwait(false))
            {
                await SyncFromStoreLockedAsync(pending, ct).ConfigureAwait(false);
                if (_session.Tokens is null)
                {
                    return;
                }
                _session = _session with { Profile = profile, ProfileETag = etag };
                await PersistLockedAsync().ConfigureAwait(false);
            }
        }
        finally
        {
            _gate.Release();
            foreach (var a in pending)
            {
                a();
            }
        }
    }

    /// <summary>Removes tokens and profile (keeps the DPoP key). Returns the removed tokens.</summary>
    internal async Task<TokenSet?> ClearAsync(CancellationToken ct)
    {
        await LoadAsync(ct).ConfigureAwait(false);
        TokenSet? old;
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await using (await AcquireLockAsync(ct).ConfigureAwait(false))
            {
                old = _session.Tokens;
                _session = new StoredSession { DPoPKey = _session.DPoPKey };
                await PersistLockedAsync().ConfigureAwait(false);
            }
        }
        finally
        {
            _gate.Release();
        }
        CancelTimer();
        if (old is not null)
        {
            _events.Raise(() => TokensChanged?.Invoke(this, new TokensChangedEventArgs(null)));
        }
        return old;
    }

    /// <summary>The installation's DPoP key; generated on first use and persisted with the next save.</summary>
    internal async Task<DPoPKey> GetOrCreateDPoPKeyAsync(CancellationToken ct)
    {
        await LoadAsync(ct).ConfigureAwait(false);
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            return EnsureKeyLocked();
        }
        finally
        {
            _gate.Release();
        }
    }

    private DPoPKey EnsureKeyLocked()
    {
        if (_dpopKey is null)
        {
            _dpopKey = DPoPKey.Generate();
            _session = _session with { DPoPKey = _dpopKey.Export() };
        }
        return _dpopKey;
    }

    private async Task<IAsyncDisposable> AcquireLockAsync(CancellationToken ct)
    {
        try
        {
            return await _lock.AcquireAsync(ct).ConfigureAwait(false);
        }
        catch (MoonSsoException)
        {
            throw;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            throw new MoonSsoException(ErrorCodes.LockTimeout, "Could not acquire the token refresh lock.", innerException: ex);
        }
    }

    /// <summary>Re-reads the store (lock held). Adopts its content when another process wrote it. Returns true when tokens were adopted.</summary>
    private async Task<bool> SyncFromStoreLockedAsync(List<Action> pending, CancellationToken ct)
    {
        StoredSession? stored;
        try
        {
            stored = await _store.LoadAsync(ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.Warning($"Could not read the token store ({ex.GetType().Name}); using in-memory tokens.");
            return false;
        }
        var fp = Fingerprint(stored?.Tokens);
        if (fp == _storeFingerprint)
        {
            // Not written by anyone else since we last saw it. Our in-memory tokens are authoritative (they may be newer if a save failed).
            if (stored?.Profile is { } sp && (_session.Profile is null || sp.ProfileVersion > _session.Profile.ProfileVersion))
            {
                _session = _session with { Profile = sp, ProfileETag = stored.ProfileETag };
            }
            return false;
        }
        _storeFingerprint = fp;
        var hadTokens = _session.Tokens is not null;
        if (stored?.Tokens is null)
        {
            _session = new StoredSession { DPoPKey = stored?.DPoPKey ?? _session.DPoPKey };
            _dpopKey = ImportKey(_session.DPoPKey) ?? _dpopKey;
            if (hadTokens)
            {
                _log.Info("Session was ended by another process sharing the token store.");
                pending.Add(() => _events.Raise(() => TokensChanged?.Invoke(this, new TokensChangedEventArgs(null))));
                pending.Add(() => _events.Raise(() => SessionExpired?.Invoke(this, new SessionExpiredEventArgs("signed out in another process"))));
            }
            return true;
        }
        _session = stored with { DPoPKey = stored.DPoPKey ?? _session.DPoPKey };
        _dpopKey = ImportKey(_session.DPoPKey) ?? _dpopKey;
        var tokens = stored.Tokens;
        pending.Add(() => _events.Raise(() => TokensChanged?.Invoke(this, new TokensChangedEventArgs(tokens))));
        return true;
    }

    private async Task ExpireLockedAsync(string reason, List<Action> pending)
    {
        _log.Info("Session expired (refresh token rejected).");
        _session = new StoredSession { DPoPKey = _session.DPoPKey };
        await PersistLockedAsync().ConfigureAwait(false);
        pending.Add(CancelTimer);
        pending.Add(() => _events.Raise(() => TokensChanged?.Invoke(this, new TokensChangedEventArgs(null))));
        pending.Add(() => _events.Raise(() => SessionExpired?.Invoke(this, new SessionExpiredEventArgs(reason))));
    }

    private async Task PersistLockedAsync(bool throwOnFailure = false)
    {
        try
        {
            // Never cancel a save: the server has already rotated the refresh token.
            await _store.SaveAsync(_session, CancellationToken.None).ConfigureAwait(false);
            _storeFingerprint = Fingerprint(_session.Tokens);
        }
        catch (Exception ex)
        {
            _log.Error($"Could not persist the session ({ex.GetType().Name}: {ex.Message}).");
            if (throwOnFailure)
            {
                throw;
            }
        }
    }

    private static string? Fingerprint(TokenSet? t) => t is null ? null : (t.RefreshToken ?? "") + "\n" + t.AccessToken;

    private DPoPKey? ImportKey(DPoPKeyData? data)
    {
        if (data is null)
        {
            return null;
        }
        if (_dpopKey is not null)
        {
            var current = _dpopKey.Export();
            if (current.X == data.X && current.Y == data.Y)
            {
                return _dpopKey;
            }
        }
        try
        {
            return DPoPKey.Import(data);
        }
        catch (Exception ex) when (ex is ArgumentException or System.Security.Cryptography.CryptographicException or FormatException)
        {
            _log.Warning("Stored DPoP key is invalid; a new key will be generated.");
            return null;
        }
    }

    private static UserProfile? MergeProfile(UserProfile? cached, UserProfile? fromToken)
    {
        if (fromToken is null || string.IsNullOrEmpty(fromToken.Sub))
        {
            return cached;
        }
        if (cached is null)
        {
            return fromToken;
        }
        if (fromToken.Sub == cached.Sub && fromToken.ProfileVersion > cached.ProfileVersion)
        {
            return fromToken with { TotpEnabled = cached.TotpEnabled };
        }
        return cached;
    }

    internal DateTimeOffset RefreshAt(TokenSet t) => t.IssuedAt + TimeSpan.FromTicks((long)(t.Lifetime.Ticks * _options.RefreshThreshold));

    internal bool NeedsRefresh(TokenSet t) => Now >= RefreshAt(t);

    private bool IsExpired(TokenSet t) => Now >= t.ExpiresAt;

    private void ScheduleTimer(TimeSpan? minimumDelay = null)
    {
        if (!_options.AutoRefresh)
        {
            return;
        }
        lock (_timerSync)
        {
            _timer?.Dispose();
            _timer = null;
            var t = _session.Tokens;
            if (_disposed || t is null || t.RefreshToken is null)
            {
                return;
            }
            var due = RefreshAt(t) - Now;
            if (minimumDelay is { } min && due < min)
            {
                due = min;
            }
            if (due < TimeSpan.FromSeconds(1))
            {
                due = TimeSpan.FromSeconds(1);
            }
            if (due > TimeSpan.FromDays(1))
            {
                due = TimeSpan.FromDays(1);
            }
            _timer = _options.TimeProvider.CreateTimer(_ => _ = OnTimerAsync(), null, due, Timeout.InfiniteTimeSpan);
        }
    }

    private void CancelTimer()
    {
        lock (_timerSync)
        {
            _timer?.Dispose();
            _timer = null;
        }
    }

    private async Task OnTimerAsync()
    {
        try
        {
            var t = _session.Tokens;
            if (t is null || _disposed)
            {
                return;
            }
            if (NeedsRefresh(t))
            {
                await RefreshCoreAsync(t.AccessToken, force: false, CancellationToken.None).ConfigureAwait(false);
            }
        }
        catch (SessionExpiredException)
        {
            return; // event already raised
        }
        catch (NotSignedInException)
        {
            return;
        }
        catch (Exception ex)
        {
            _log.Warning($"Background token refresh failed ({(ex as MoonSsoException)?.Error ?? ex.GetType().Name}); retrying in {RetryAfterFailure.TotalSeconds:0} s.");
        }
        var cur = _session.Tokens;
        if (cur is not null && NeedsRefresh(cur))
        {
            ScheduleTimer(RetryAfterFailure);
        }
        else
        {
            ScheduleTimer();
        }
    }

    public ValueTask DisposeAsync()
    {
        lock (_timerSync)
        {
            _disposed = true;
            _timer?.Dispose();
            _timer = null;
        }
        return ValueTask.CompletedTask;
    }
}

/// <summary>Raises SDK events either inline or on the configured synchronization context; handler exceptions are logged, never propagated.</summary>
internal sealed class EventDispatcher
{
    private readonly SynchronizationContext? _context;
    private readonly Logger _log;

    public EventDispatcher(SynchronizationContext? context, Logger log)
    {
        _context = context;
        _log = log;
    }

    public void Raise(Action action)
    {
        if (_context is not null)
        {
            _context.Post(_ => Invoke(action), null);
        }
        else
        {
            Invoke(action);
        }
    }

    private void Invoke(Action action)
    {
        try
        {
            action();
        }
        catch (Exception ex)
        {
            _log.Error($"An event handler threw {ex.GetType().Name}: {ex.Message}");
        }
    }
}
