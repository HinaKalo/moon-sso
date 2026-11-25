using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using MoonSso.Internal;

namespace MoonSso;

/// <summary>Serialized DPoP private key (EC P-256 JWK including <c>d</c>). Keep it in secure storage only.</summary>
public sealed record DPoPKeyData
{
    [JsonPropertyName("kty")] public string Kty { get; init; } = "EC";
    [JsonPropertyName("crv")] public string Crv { get; init; } = "P-256";
    [JsonPropertyName("x")] public string X { get; init; } = "";
    [JsonPropertyName("y")] public string Y { get; init; } = "";
    [JsonPropertyName("d")] public string D { get; init; } = "";

    public override string ToString() => "DPoPKeyData { kty = EC, crv = P-256 }";
}

/// <summary>A per-installation P-256 key used to create DPoP proofs (RFC 9449).</summary>
public sealed class DPoPKey : IDisposable
{
    private readonly ECDsa _ec;
    private readonly string _publicJwkJson;

    private DPoPKey(ECDsa ec)
    {
        _ec = ec;
        var p = ec.ExportParameters(false);
        X = Base64Url.Encode(p.Q.X);
        Y = Base64Url.Encode(p.Q.Y);
        // RFC 7638: required members in lexicographic order, no whitespace.
        _publicJwkJson = "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"" + X + "\",\"y\":\"" + Y + "\"}";
        Thumbprint = Base64Url.Encode(SHA256.HashData(Encoding.UTF8.GetBytes(_publicJwkJson)));
    }

    internal string X { get; }
    internal string Y { get; }

    /// <summary>base64url(SHA-256 JWK thumbprint), sent as <c>dpop_jkt</c>.</summary>
    public string Thumbprint { get; }

    /// <summary>Generates a new P-256 key.</summary>
    public static DPoPKey Generate() => new(ECDsa.Create(ECCurve.NamedCurves.nistP256));

    /// <summary>Restores a key saved with <see cref="Export"/>.</summary>
    public static DPoPKey Import(DPoPKeyData data)
    {
        ArgumentNullException.ThrowIfNull(data);
        if (data.Kty != "EC" || data.Crv != "P-256")
        {
            throw new ArgumentException("Only EC P-256 DPoP keys are supported.", nameof(data));
        }
        var ec = ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = Base64Url.Decode(data.D),
            Q = new ECPoint { X = Base64Url.Decode(data.X), Y = Base64Url.Decode(data.Y) },
        });
        return new DPoPKey(ec);
    }

    /// <summary>Exports the private key for secure storage.</summary>
    public DPoPKeyData Export()
    {
        var p = _ec.ExportParameters(true);
        return new DPoPKeyData { X = Base64Url.Encode(p.Q.X), Y = Base64Url.Encode(p.Q.Y), D = Base64Url.Encode(p.D) };
    }

    /// <summary>
    /// Creates a proof JWT: header <c>{"typ":"dpop+jwt","alg":"ES256","jwk":{kty,crv,x,y}}</c>,
    /// claims <c>{jti, htm, htu, iat, nonce?, ath?}</c>.
    /// </summary>
    public string CreateProof(string method, string url, string? nonce, DateTimeOffset now, string? accessToken = null)
    {
        var htu = url;
        var cut = htu.IndexOfAny(new[] { '?', '#' });
        if (cut >= 0)
        {
            htu = htu[..cut];
        }
        var header = "{\"typ\":\"dpop+jwt\",\"alg\":\"ES256\",\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"" + X + "\",\"y\":\"" + Y + "\"}}";
        using var ms = new MemoryStream();
        using (var w = new Utf8JsonWriter(ms))
        {
            w.WriteStartObject();
            w.WriteString("jti", Base64Url.Random(16));
            w.WriteString("htm", method.ToUpperInvariant());
            w.WriteString("htu", htu);
            w.WriteNumber("iat", now.ToUnixTimeSeconds());
            if (!string.IsNullOrEmpty(nonce))
            {
                w.WriteString("nonce", nonce);
            }
            if (accessToken is not null)
            {
                w.WriteString("ath", Base64Url.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(accessToken))));
            }
            w.WriteEndObject();
        }
        var signingInput = Base64Url.Encode(Encoding.UTF8.GetBytes(header)) + "." + Base64Url.Encode(ms.ToArray());
        var sig = _ec.SignData(Encoding.ASCII.GetBytes(signingInput), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        return signingInput + "." + Base64Url.Encode(sig);
    }

    public void Dispose() => _ec.Dispose();

    public override string ToString() => $"DPoPKey {{ Thumbprint = {Thumbprint} }}";
}

/// <summary>Remembers the latest <c>DPoP-Nonce</c> per server origin.</summary>
internal sealed class DPoPNonceCache
{
    private readonly ConcurrentDictionary<string, string> _nonces = new(StringComparer.OrdinalIgnoreCase);

    public string? Get(Uri url) => _nonces.TryGetValue(url.GetLeftPart(UriPartial.Authority), out var n) ? n : null;

    public void Update(Uri url, HttpResponseMessage response)
    {
        if (response.Headers.TryGetValues("DPoP-Nonce", out var values))
        {
            var n = values.FirstOrDefault();
            if (!string.IsNullOrEmpty(n))
            {
                _nonces[url.GetLeftPart(UriPartial.Authority)] = n;
            }
        }
    }
}
