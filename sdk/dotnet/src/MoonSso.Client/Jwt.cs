using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using MoonSso.Internal;

namespace MoonSso;

/// <summary>A parsed compact JWS (header.payload.signature). Parsing does not verify anything.</summary>
public sealed class JwsToken
{
    private JwsToken(JsonElement header, JsonElement payload, byte[] signingInput, byte[] signature)
    {
        Header = header;
        Payload = payload;
        SigningInput = signingInput;
        Signature = signature;
    }

    public JsonElement Header { get; }
    public JsonElement Payload { get; }
    internal byte[] SigningInput { get; }
    internal byte[] Signature { get; }

    public string Alg => Header.GetString("alg") ?? "";
    public string? Kid => Header.GetString("kid");
    public string? Typ => Header.GetString("typ");

    /// <summary>Parses a compact JWS. Throws <see cref="MoonSsoException"/> (<c>invalid_token</c>) when malformed.</summary>
    public static JwsToken Parse(string compact)
    {
        if (string.IsNullOrEmpty(compact) || compact.Length > 16384)
        {
            throw Invalid("Token is empty or too large.");
        }
        var parts = compact.Split('.');
        if (parts.Length != 3)
        {
            throw Invalid("Token is not a compact JWS.");
        }
        if (!Base64Url.TryDecode(parts[0], out var h) || !Base64Url.TryDecode(parts[1], out var p) || !Base64Url.TryDecode(parts[2], out var sig))
        {
            throw Invalid("Token segments are not base64url.");
        }
        JsonElement header, payload;
        try
        {
            using (var hd = JsonDocument.Parse(h))
            {
                header = hd.RootElement.Clone();
            }
            using (var pd = JsonDocument.Parse(p))
            {
                payload = pd.RootElement.Clone();
            }
        }
        catch (JsonException ex)
        {
            throw new MoonSsoException("invalid_token", "Token header or payload is not JSON.", innerException: ex);
        }
        if (header.ValueKind != JsonValueKind.Object || payload.ValueKind != JsonValueKind.Object)
        {
            throw Invalid("Token header and payload must be JSON objects.");
        }
        return new JwsToken(header, payload, Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]), sig);
    }

    private static MoonSsoException Invalid(string d) => new("invalid_token", d);
}

/// <summary>Verified JWT claims.</summary>
public sealed class JwtClaims
{
    internal JwtClaims(JsonElement root, JwsToken token)
    {
        Root = root;
        Token = token;
    }

    /// <summary>The raw claims object.</summary>
    public JsonElement Root { get; }

    /// <summary>The token the claims came from (header access).</summary>
    public JwsToken Token { get; }

    public string? Issuer => Root.GetString("iss");
    public string? Subject => Root.GetString("sub");
    public string? Nonce => Root.GetString("nonce");
    public string? SessionId => Root.GetString("sid");
    public string? JwtId => Root.GetString("jti");
    public string? AuthorizedParty => Root.GetString("azp");
    public string? ClientId => Root.GetString("client_id");
    public string? Scope => Root.GetString("scope");
    public long? ExpiresAt => Root.GetInt64("exp");
    public long? IssuedAt => Root.GetInt64("iat");
    public long? NotBefore => Root.GetInt64("nbf");

    public IReadOnlyList<string> Audiences
    {
        get
        {
            if (!Root.TryGetProperty("aud", out var aud))
            {
                return Array.Empty<string>();
            }
            return aud.ValueKind switch
            {
                JsonValueKind.String => new[] { aud.GetString()! },
                JsonValueKind.Array => aud.EnumerateArray().Where(a => a.ValueKind == JsonValueKind.String).Select(a => a.GetString()!).ToArray(),
                _ => Array.Empty<string>(),
            };
        }
    }

    public string? GetString(string name) => Root.GetString(name);

    public long? GetInt64(string name) => Root.GetInt64(name);

    public bool TryGetProperty(string name, out JsonElement value) => Root.TryGetProperty(name, out value);

    internal UserProfile ToProfile() => new()
    {
        Sub = Subject ?? "",
        PreferredUsername = GetString("preferred_username"),
        Name = GetString("name"),
        Nickname = GetString("nickname"),
        Picture = GetString("picture"),
        UpdatedAt = GetInt64("updated_at") ?? 0,
        ProfileVersion = GetInt64("profile_version") ?? 0,
    };
}

/// <summary>Signature verification with BCL crypto only (RSA PKCS#1 v1.5 / PSS, ECDSA P-256/384/521).</summary>
public static class JwsVerifier
{
    /// <summary>Algorithms accepted for issuer-signed tokens. <c>none</c> and HMAC are never accepted.</summary>
    public static readonly IReadOnlySet<string> SupportedAlgorithms =
        new HashSet<string>(StringComparer.Ordinal) { "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512" };

    /// <summary>Verifies the token signature with <paramref name="key"/>.</summary>
    public static bool Verify(JwsToken token, JsonWebKey key)
    {
        ArgumentNullException.ThrowIfNull(token);
        ArgumentNullException.ThrowIfNull(key);
        var alg = token.Alg;
        if (!SupportedAlgorithms.Contains(alg) || (key.Alg is not null && key.Alg != alg))
        {
            return false;
        }
        var hash = HashFor(alg);
        try
        {
            if (alg[0] == 'E')
            {
                if (key.Kty != "EC" || key.X is null || key.Y is null)
                {
                    return false;
                }
                var (curve, size) = alg switch
                {
                    "ES256" => (ECCurve.NamedCurves.nistP256, 32),
                    "ES384" => (ECCurve.NamedCurves.nistP384, 48),
                    _ => (ECCurve.NamedCurves.nistP521, 66),
                };
                var expectedCrv = alg switch { "ES256" => "P-256", "ES384" => "P-384", _ => "P-521" };
                if (key.Crv != expectedCrv || token.Signature.Length != size * 2)
                {
                    return false;
                }
                using var ec = ECDsa.Create(new ECParameters
                {
                    Curve = curve,
                    Q = new ECPoint { X = Pad(Base64Url.Decode(key.X), size), Y = Pad(Base64Url.Decode(key.Y), size) },
                });
                return ec.VerifyData(token.SigningInput, token.Signature, hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            }
            if (key.Kty != "RSA" || key.N is null || key.E is null)
            {
                return false;
            }
            var modulus = Base64Url.Decode(key.N);
            if (modulus.Length * 8 < 2040)
            {
                return false; // RSA keys shorter than 2048 bits are rejected
            }
            using var rsa = RSA.Create(new RSAParameters { Modulus = modulus, Exponent = Base64Url.Decode(key.E) });
            var padding = alg[0] == 'P' ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;
            return rsa.VerifyData(token.SigningInput, token.Signature, hash, padding);
        }
        catch (CryptographicException)
        {
            return false;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    internal static HashAlgorithmName HashFor(string alg) => alg[^3..] switch
    {
        "256" => HashAlgorithmName.SHA256,
        "384" => HashAlgorithmName.SHA384,
        "512" => HashAlgorithmName.SHA512,
        _ => throw new NotSupportedException("Unsupported algorithm."),
    };

    private static byte[] Pad(byte[] b, int size)
    {
        if (b.Length == size)
        {
            return b;
        }
        if (b.Length > size)
        {
            throw new CryptographicException("EC coordinate too long.");
        }
        var r = new byte[size];
        Buffer.BlockCopy(b, 0, r, size - b.Length, b.Length);
        return r;
    }
}

/// <summary>
/// Validates ID tokens, access tokens (resource server use) and logout tokens issued by Moon SSO,
/// using keys from a <see cref="JwksCache"/>.
/// </summary>
public sealed class TokenValidator
{
    private readonly JwksCache _jwks;
    private readonly string _issuer;
    private readonly TimeProvider _time;

    public TokenValidator(JwksCache jwks, string issuer, TimeProvider? timeProvider = null, TimeSpan? clockSkew = null)
    {
        _jwks = jwks ?? throw new ArgumentNullException(nameof(jwks));
        _issuer = DiscoveryCache.NormalizeIssuer(issuer);
        _time = timeProvider ?? TimeProvider.System;
        ClockSkew = clockSkew ?? TimeSpan.FromSeconds(60);
    }

    /// <summary>Allowed clock difference for exp/iat/nbf (default 60 seconds).</summary>
    public TimeSpan ClockSkew { get; }

    /// <summary>Parses the token, finds the signing key and verifies the signature. No claim checks.</summary>
    public async Task<JwtClaims> VerifySignatureAsync(string jwt, string errorCode = "invalid_token", CancellationToken cancellationToken = default)
    {
        JwsToken token;
        try
        {
            token = JwsToken.Parse(jwt);
        }
        catch (MoonSsoException ex)
        {
            throw new MoonSsoException(errorCode, ex.ErrorDescription, innerException: ex);
        }
        if (!JwsVerifier.SupportedAlgorithms.Contains(token.Alg))
        {
            throw new MoonSsoException(errorCode, "Unsupported or missing signing algorithm.");
        }
        if (token.Header.TryGetProperty("crit", out _))
        {
            throw new MoonSsoException(errorCode, "Unsupported critical header.");
        }
        var key = await _jwks.GetKeyAsync(token.Kid, token.Alg, cancellationToken).ConfigureAwait(false)
                  ?? throw new MoonSsoException(errorCode, "No matching signing key in JWKS.");
        if (!JwsVerifier.Verify(token, key))
        {
            throw new MoonSsoException(errorCode, "Signature verification failed.");
        }
        return new JwtClaims(token.Payload, token);
    }

    /// <summary>
    /// Validates an ID token: signature, <c>iss</c>, <c>aud</c> contains <paramref name="clientId"/> (and <c>azp</c> when there are several
    /// audiences), <c>exp</c>, <c>iat</c> (±skew), <c>nonce</c> when <paramref name="expectedNonce"/> is given, and <c>at_hash</c> when present.
    /// </summary>
    public async Task<JwtClaims> ValidateIdTokenAsync(string idToken, string clientId, string? expectedNonce = null, string? accessToken = null, CancellationToken cancellationToken = default)
    {
        const string code = ErrorCodes.InvalidIdToken;
        var claims = await VerifySignatureAsync(idToken, code, cancellationToken).ConfigureAwait(false);
        CheckIssuer(claims, code);
        var aud = claims.Audiences;
        if (!aud.Contains(clientId))
        {
            throw new MoonSsoException(code, "ID token audience does not contain this client.");
        }
        if (aud.Count > 1 && claims.AuthorizedParty != clientId)
        {
            throw new MoonSsoException(code, "ID token azp does not match this client.");
        }
        CheckTimes(claims, code, requireExp: true);
        if (claims.IssuedAt is null)
        {
            throw new MoonSsoException(code, "ID token has no iat.");
        }
        if (expectedNonce is not null && !FixedEquals(claims.Nonce, expectedNonce))
        {
            throw new MoonSsoException(code, "ID token nonce mismatch.");
        }
        var atHash = claims.GetString("at_hash");
        if (atHash is not null && accessToken is not null)
        {
            var h = HashData(JwsVerifier.HashFor(claims.Token.Alg), Encoding.ASCII.GetBytes(accessToken));
            var expected = Base64Url.Encode(h.AsSpan(0, h.Length / 2));
            if (!FixedEquals(atHash, expected))
            {
                throw new MoonSsoException(code, "ID token at_hash mismatch.");
            }
        }
        return claims;
    }

    /// <summary>
    /// Validates an access token for a resource server: signature, header <c>typ == at+jwt</c>, <c>iss</c>, <c>exp</c>, <c>nbf</c>
    /// and that <c>aud</c> contains <paramref name="expectedAudience"/> (the client_id or the configured resource).
    /// </summary>
    public async Task<JwtClaims> ValidateAccessTokenAsync(string accessToken, string expectedAudience, CancellationToken cancellationToken = default)
    {
        const string code = "invalid_token";
        var claims = await VerifySignatureAsync(accessToken, code, cancellationToken).ConfigureAwait(false);
        var typ = claims.Token.Typ;
        if (!string.Equals(typ, "at+jwt", StringComparison.OrdinalIgnoreCase) && !string.Equals(typ, "application/at+jwt", StringComparison.OrdinalIgnoreCase))
        {
            throw new MoonSsoException(code, "Token is not an access token (typ).");
        }
        CheckIssuer(claims, code);
        CheckTimes(claims, code, requireExp: true);
        if (!claims.Audiences.Contains(expectedAudience))
        {
            throw new MoonSsoException(code, "Access token audience mismatch.");
        }
        return claims;
    }

    internal void CheckIssuer(JwtClaims claims, string code)
    {
        if (claims.Issuer is null || claims.Issuer.TrimEnd('/') != _issuer)
        {
            throw new MoonSsoException(code, "Issuer mismatch.");
        }
    }

    internal void CheckTimes(JwtClaims claims, string code, bool requireExp)
    {
        var now = _time.GetUtcNow().ToUnixTimeSeconds();
        var skew = (long)ClockSkew.TotalSeconds;
        var exp = claims.ExpiresAt;
        if (exp is null && requireExp)
        {
            throw new MoonSsoException(code, "Token has no exp.");
        }
        if (exp is not null && now - skew >= exp)
        {
            throw new MoonSsoException(code, "Token expired.");
        }
        if (claims.IssuedAt is { } iat && iat > now + skew)
        {
            throw new MoonSsoException(code, "Token issued in the future.");
        }
        if (claims.NotBefore is { } nbf && nbf > now + skew)
        {
            throw new MoonSsoException(code, "Token not yet valid.");
        }
    }

    internal DateTimeOffset UtcNow => _time.GetUtcNow();

    private static byte[] HashData(HashAlgorithmName name, byte[] data)
    {
        if (name == HashAlgorithmName.SHA384)
        {
            return SHA384.HashData(data);
        }
        if (name == HashAlgorithmName.SHA512)
        {
            return SHA512.HashData(data);
        }
        return SHA256.HashData(data);
    }

    internal static bool FixedEquals(string? a, string? b)
    {
        if (a is null || b is null)
        {
            return false;
        }
        return CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(a), Encoding.UTF8.GetBytes(b));
    }
}
