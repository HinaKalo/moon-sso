using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using MoonSso.Internal;

namespace MoonSso;

/// <summary>A public JSON Web Key (RFC 7517) as published in the JWKS.</summary>
public sealed record JsonWebKey
{
    [JsonPropertyName("kty")] public string Kty { get; init; } = "";
    [JsonPropertyName("kid")] public string? Kid { get; init; }
    [JsonPropertyName("alg")] public string? Alg { get; init; }
    [JsonPropertyName("use")] public string? Use { get; init; }
    [JsonPropertyName("n")] public string? N { get; init; }
    [JsonPropertyName("e")] public string? E { get; init; }
    [JsonPropertyName("crv")] public string? Crv { get; init; }
    [JsonPropertyName("x")] public string? X { get; init; }
    [JsonPropertyName("y")] public string? Y { get; init; }

    /// <summary>Creates the public JWK of an RSA key.</summary>
    public static JsonWebKey FromRsa(RSA rsa, string? kid = null, string? alg = "RS256")
    {
        var p = rsa.ExportParameters(false);
        return new JsonWebKey { Kty = "RSA", Kid = kid, Alg = alg, Use = "sig", N = Base64Url.Encode(p.Modulus), E = Base64Url.Encode(p.Exponent) };
    }

    /// <summary>Creates the public JWK of an EC key (P-256/384/521).</summary>
    public static JsonWebKey FromECDsa(ECDsa ec, string? kid = null, string? alg = null)
    {
        var p = ec.ExportParameters(false);
        var crv = CurveName(p.Curve);
        return new JsonWebKey { Kty = "EC", Kid = kid, Alg = alg, Use = "sig", Crv = crv, X = Base64Url.Encode(p.Q.X), Y = Base64Url.Encode(p.Q.Y) };
    }

    internal static string CurveName(ECCurve curve)
    {
        var oid = curve.Oid?.Value;
        var name = curve.Oid?.FriendlyName;
        return oid switch
        {
            "1.2.840.10045.3.1.7" => "P-256",
            "1.3.132.0.34" => "P-384",
            "1.3.132.0.35" => "P-521",
            _ => name switch
            {
                "nistP256" or "ECDSA_P256" => "P-256",
                "nistP384" or "ECDSA_P384" => "P-384",
                "nistP521" or "ECDSA_P521" => "P-521",
                _ => throw new NotSupportedException("Unsupported EC curve."),
            },
        };
    }
}

/// <summary>A JSON Web Key Set.</summary>
public sealed record JsonWebKeySet
{
    [JsonPropertyName("keys")] public IReadOnlyList<JsonWebKey> Keys { get; init; } = Array.Empty<JsonWebKey>();
}

/// <summary>
/// Caches the issuer's JWKS for one hour. An unknown <c>kid</c> forces a refetch, at most once every 30 seconds.
/// A failed refetch keeps using the stale keys.
/// </summary>
public sealed class JwksCache
{
    private static readonly TimeSpan Ttl = TimeSpan.FromHours(1);
    private static readonly TimeSpan MinForcedInterval = TimeSpan.FromSeconds(30);

    private readonly Func<CancellationToken, Task<JsonWebKeySet>> _fetch;
    private readonly TimeProvider _time;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private JsonWebKeySet? _keys;
    private DateTimeOffset _fetchedAt;
    private DateTimeOffset _lastForced = DateTimeOffset.MinValue;

    /// <summary>Fetches keys from the <c>jwks_uri</c> advertised by discovery.</summary>
    public JwksCache(HttpClient http, DiscoveryCache discovery, TimeProvider? timeProvider = null)
        : this(ct => FetchAsync(http, discovery, ct), timeProvider)
    {
    }

    /// <summary>Uses a custom key source (e.g. a static key set in tests or air-gapped resource servers).</summary>
    public JwksCache(Func<CancellationToken, Task<JsonWebKeySet>> fetch, TimeProvider? timeProvider = null)
    {
        _fetch = fetch ?? throw new ArgumentNullException(nameof(fetch));
        _time = timeProvider ?? TimeProvider.System;
    }

    /// <summary>Static key set that never changes.</summary>
    public static JwksCache FromKeys(JsonWebKeySet keys, TimeProvider? timeProvider = null) => new(_ => Task.FromResult(keys), timeProvider);

    /// <summary>Finds the key for <paramref name="kid"/> usable with <paramref name="alg"/>, refetching once if unknown.</summary>
    public async Task<JsonWebKey?> GetKeyAsync(string? kid, string alg, CancellationToken cancellationToken = default)
    {
        var set = await GetSetAsync(force: false, cancellationToken).ConfigureAwait(false);
        var key = Find(set, kid, alg);
        if (key is not null)
        {
            return key;
        }
        set = await GetSetAsync(force: true, cancellationToken).ConfigureAwait(false);
        return Find(set, kid, alg);
    }

    private static JsonWebKey? Find(JsonWebKeySet? set, string? kid, string alg)
    {
        if (set is null)
        {
            return null;
        }
        var kty = alg.StartsWith("ES", StringComparison.Ordinal) ? "EC" : "RSA";
        var candidates = set.Keys.Where(k => k.Kty == kty && (k.Use is null || k.Use == "sig") && (k.Alg is null || k.Alg == alg));
        if (kid is not null)
        {
            return candidates.FirstOrDefault(k => k.Kid == kid);
        }
        var list = candidates.ToList();
        return list.Count == 1 ? list[0] : null;
    }

    private async Task<JsonWebKeySet?> GetSetAsync(bool force, CancellationToken ct)
    {
        var now = _time.GetUtcNow();
        if (!force && _keys is not null && now - _fetchedAt < Ttl)
        {
            return _keys;
        }
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            now = _time.GetUtcNow();
            if (force)
            {
                if (now - _lastForced < MinForcedInterval)
                {
                    return _keys;
                }
                _lastForced = now;
            }
            else if (_keys is not null && now - _fetchedAt < Ttl)
            {
                return _keys;
            }
            try
            {
                _keys = await _fetch(ct).ConfigureAwait(false);
                _fetchedAt = now;
            }
            catch (MoonSsoException) when (_keys is not null && !ct.IsCancellationRequested)
            {
                // stale keys keep working
            }
            return _keys;
        }
        finally
        {
            _gate.Release();
        }
    }

    private static async Task<JsonWebKeySet> FetchAsync(HttpClient http, DiscoveryCache discovery, CancellationToken ct)
    {
        var doc = await discovery.GetAsync(ct).ConfigureAwait(false);
        using var req = new HttpRequestMessage(HttpMethod.Get, doc.JwksUri);
        req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        try
        {
            using var resp = await http.SendAsync(req, ct).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode)
            {
                throw new MoonSsoException(ErrorCodes.Network, "JWKS request failed.", (int)resp.StatusCode);
            }
            await using var s = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
            return await JsonSerializer.DeserializeAsync<JsonWebKeySet>(s, Json.Options, ct).ConfigureAwait(false)
                   ?? throw new MoonSsoException(ErrorCodes.InvalidResponse, "Empty JWKS.");
        }
        catch (JsonException ex)
        {
            throw new MoonSsoException(ErrorCodes.InvalidResponse, "Malformed JWKS.", innerException: ex);
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException || (ex is TaskCanceledException && !ct.IsCancellationRequested))
        {
            throw new MoonSsoException(ErrorCodes.Network, "JWKS request failed.", innerException: ex);
        }
    }
}
