using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using MoonSso;
using MoonSso.Internal;

namespace MoonSso.Tests.Unit;

internal static class TestJwt
{
    public static string Sign(object header, object payload, AsymmetricAlgorithm key, string alg)
    {
        var h = Base64Url.Encode(JsonSerializer.SerializeToUtf8Bytes(header));
        var p = Base64Url.Encode(JsonSerializer.SerializeToUtf8Bytes(payload));
        var input = Encoding.ASCII.GetBytes(h + "." + p);
        var hash = JwsVerifier.HashFor(alg);
        byte[] sig = key switch
        {
            RSA rsa => rsa.SignData(input, hash, alg.StartsWith("PS") ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1),
            ECDsa ec => ec.SignData(input, hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation),
            _ => throw new NotSupportedException(),
        };
        return h + "." + p + "." + Base64Url.Encode(sig);
    }
}

public class JwsTests : IDisposable
{
    private const string Issuer = "https://sso.example.test";
    private const string ClientId = "client-1";
    private readonly RSA _rsa = RSA.Create(2048);
    private readonly ECDsa _ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ECDsa _ec384 = ECDsa.Create(ECCurve.NamedCurves.nistP384);
    private readonly FixedTime _time = new(DateTimeOffset.FromUnixTimeSeconds(1_800_000_000));
    private readonly TokenValidator _validator;

    public JwsTests()
    {
        var keys = new JsonWebKeySet
        {
            Keys = new[]
            {
                JsonWebKey.FromRsa(_rsa, "rsa1", "RS256"),
                JsonWebKey.FromECDsa(_ec, "ec1", "ES256"),
                JsonWebKey.FromECDsa(_ec384, "ec384", "ES384"),
            },
        };
        _validator = new TokenValidator(JwksCache.FromKeys(keys, _time), Issuer, _time);
    }

    private long Now => _time.GetUtcNow().ToUnixTimeSeconds();

    private Dictionary<string, object> IdClaims(string? nonce = "n-1")
    {
        var c = new Dictionary<string, object> { ["iss"] = Issuer, ["sub"] = "user-1", ["aud"] = ClientId, ["exp"] = Now + 300, ["iat"] = Now, ["name"] = "Alice", ["profile_version"] = 4 };
        if (nonce is not null)
        {
            c["nonce"] = nonce;
        }
        return c;
    }

    [Fact]
    public async Task ValidIdToken_Rs256_And_Es256()
    {
        var rs = TestJwt.Sign(new { alg = "RS256", kid = "rsa1", typ = "JWT" }, IdClaims(), _rsa, "RS256");
        var claims = await _validator.ValidateIdTokenAsync(rs, ClientId, "n-1");
        Assert.Equal("user-1", claims.Subject);
        Assert.Equal("Alice", claims.ToProfile().Name);
        Assert.Equal(4, claims.ToProfile().ProfileVersion);

        var es = TestJwt.Sign(new { alg = "ES256", kid = "ec1" }, IdClaims(), _ec, "ES256");
        Assert.Equal("user-1", (await _validator.ValidateIdTokenAsync(es, ClientId, "n-1")).Subject);

        var es384 = TestJwt.Sign(new { alg = "ES384", kid = "ec384" }, IdClaims(), _ec384, "ES384");
        Assert.Equal("user-1", (await _validator.ValidateIdTokenAsync(es384, ClientId, "n-1")).Subject);
    }

    [Fact]
    public async Task AtHash_IsChecked()
    {
        const string at = "access-token-value";
        var h = SHA256.HashData(Encoding.ASCII.GetBytes(at));
        var claims = IdClaims();
        claims["at_hash"] = Base64Url.Encode(h.AsSpan(0, 16));
        var tok = TestJwt.Sign(new { alg = "RS256", kid = "rsa1" }, claims, _rsa, "RS256");
        await _validator.ValidateIdTokenAsync(tok, ClientId, "n-1", at);
        var ex = await Assert.ThrowsAsync<MoonSsoException>(() => _validator.ValidateIdTokenAsync(tok, ClientId, "n-1", at + "x"));
        Assert.Equal(ErrorCodes.InvalidIdToken, ex.Error);
    }

    [Fact]
    public async Task RejectsBadSignaturesAndClaims()
    {
        async Task Fails(string token, string? nonce = "n-1")
        {
            var ex = await Assert.ThrowsAsync<MoonSsoException>(() => _validator.ValidateIdTokenAsync(token, ClientId, nonce));
            Assert.Equal(ErrorCodes.InvalidIdToken, ex.Error);
        }

        var good = TestJwt.Sign(new { alg = "RS256", kid = "rsa1" }, IdClaims(), _rsa, "RS256");
        var parts = good.Split('.');
        // tampered payload
        var c = IdClaims();
        c["sub"] = "mallory";
        await Fails(parts[0] + "." + Base64Url.Encode(JsonSerializer.SerializeToUtf8Bytes(c)) + "." + parts[2]);
        // alg none / HS256
        await Fails(Base64Url.Encode("{\"alg\":\"none\"}"u8) + "." + parts[1] + ".");
        await Fails(Base64Url.Encode("{\"alg\":\"HS256\",\"kid\":\"rsa1\"}"u8) + "." + parts[1] + "." + parts[2]);
        // key confusion: RS256 header with EC kid
        await Fails(TestJwt.Sign(new { alg = "RS256", kid = "ec1" }, IdClaims(), _rsa, "RS256"));
        // signed by an unknown key
        using var other = RSA.Create(2048);
        await Fails(TestJwt.Sign(new { alg = "RS256", kid = "rsa1" }, IdClaims(), other, "RS256"));
        // wrong issuer, audience, nonce, expired, future iat
        var wrongIss = IdClaims(); wrongIss["iss"] = "https://evil.test";
        await Fails(TestJwt.Sign(new { alg = "RS256", kid = "rsa1" }, wrongIss, _rsa, "RS256"));
        var wrongAud = IdClaims(); wrongAud["aud"] = "other-client";
        await Fails(TestJwt.Sign(new { alg = "RS256", kid = "rsa1" }, wrongAud, _rsa, "RS256"));
        var multiAud = IdClaims(); multiAud["aud"] = new[] { ClientId, "other" };
        await Fails(TestJwt.Sign(new { alg = "RS256", kid = "rsa1" }, multiAud, _rsa, "RS256")); // azp missing
        await Fails(good, "n-2");
        var expired = IdClaims(); expired["exp"] = Now - 61;
        await Fails(TestJwt.Sign(new { alg = "RS256", kid = "rsa1" }, expired, _rsa, "RS256"));
        var future = IdClaims(); future["iat"] = Now + 120;
        await Fails(TestJwt.Sign(new { alg = "RS256", kid = "rsa1" }, future, _rsa, "RS256"));
        await Fails("not.a.jwt");
    }

    [Fact]
    public async Task ClockSkewIsAllowed()
    {
        var claims = IdClaims();
        claims["exp"] = Now - 30;
        claims["iat"] = Now + 30;
        await _validator.ValidateIdTokenAsync(TestJwt.Sign(new { alg = "RS256", kid = "rsa1" }, claims, _rsa, "RS256"), ClientId, "n-1");
    }

    [Fact]
    public async Task AccessToken_RequiresTypAndAudience()
    {
        var claims = new Dictionary<string, object> { ["iss"] = Issuer, ["sub"] = "u", ["aud"] = new[] { ClientId, Issuer + "/api" }, ["exp"] = Now + 60, ["iat"] = Now, ["nbf"] = Now - 5, ["scope"] = "openid profile" };
        var at = TestJwt.Sign(new { alg = "ES256", kid = "ec1", typ = "at+jwt" }, claims, _ec, "ES256");
        var c = await _validator.ValidateAccessTokenAsync(at, Issuer + "/api");
        Assert.Equal("openid profile", c.Scope);
        await Assert.ThrowsAsync<MoonSsoException>(() => _validator.ValidateAccessTokenAsync(at, "someone-else"));
        var idTyp = TestJwt.Sign(new { alg = "ES256", kid = "ec1", typ = "JWT" }, claims, _ec, "ES256");
        await Assert.ThrowsAsync<MoonSsoException>(() => _validator.ValidateAccessTokenAsync(idTyp, ClientId));
        claims["nbf"] = Now + 600;
        var notYet = TestJwt.Sign(new { alg = "ES256", kid = "ec1", typ = "at+jwt" }, claims, _ec, "ES256");
        await Assert.ThrowsAsync<MoonSsoException>(() => _validator.ValidateAccessTokenAsync(notYet, ClientId));
    }

    [Fact]
    public async Task UnknownKid_RefetchesAtMostEvery30Seconds()
    {
        var fetches = 0;
        var keys = new JsonWebKeySet { Keys = new[] { JsonWebKey.FromRsa(_rsa, "rsa1", "RS256") } };
        var cache = new JwksCache(_ => { fetches++; return Task.FromResult(keys); }, _time);
        Assert.NotNull(await cache.GetKeyAsync("rsa1", "RS256"));
        Assert.Equal(1, fetches);
        Assert.Null(await cache.GetKeyAsync("missing", "RS256"));
        Assert.Equal(2, fetches);
        Assert.Null(await cache.GetKeyAsync("missing", "RS256"));
        Assert.Equal(2, fetches); // rate limited
        _time.Advance(TimeSpan.FromSeconds(31));
        Assert.Null(await cache.GetKeyAsync("missing", "RS256"));
        Assert.Equal(3, fetches);
        _time.Advance(TimeSpan.FromHours(1));
        Assert.NotNull(await cache.GetKeyAsync("rsa1", "RS256"));
        Assert.Equal(4, fetches); // TTL expired
    }

    [Fact]
    public async Task BackchannelLogoutToken_Validation()
    {
        var verifier = new BackchannelLogoutVerifier(_validator, ClientId);
        Dictionary<string, object> Claims() => new()
        {
            ["iss"] = Issuer, ["aud"] = ClientId, ["iat"] = Now, ["exp"] = Now + 120, ["jti"] = Guid.NewGuid().ToString("N"), ["sub"] = "user-1", ["sid"] = "sid-1",
            ["events"] = new Dictionary<string, object> { ["http://schemas.openid.net/event/backchannel-logout"] = new Dictionary<string, object>() },
        };
        string Sign(Dictionary<string, object> c, string typ = "logout+jwt") => TestJwt.Sign(new { alg = "RS256", kid = "rsa1", typ }, c, _rsa, "RS256");

        var ok = Sign(Claims());
        var result = await verifier.ValidateAsync(ok);
        Assert.Equal("user-1", result.Subject);
        Assert.Equal("sid-1", result.SessionId);
        await Assert.ThrowsAsync<MoonSsoException>(() => verifier.ValidateAsync(ok)); // replayed jti

        await Assert.ThrowsAsync<MoonSsoException>(() => verifier.ValidateAsync(Sign(Claims(), "JWT")));
        var noEvent = Claims(); noEvent.Remove("events");
        await Assert.ThrowsAsync<MoonSsoException>(() => verifier.ValidateAsync(Sign(noEvent)));
        var withNonce = Claims(); withNonce["nonce"] = "x";
        await Assert.ThrowsAsync<MoonSsoException>(() => verifier.ValidateAsync(Sign(withNonce)));
        var noSubject = Claims(); noSubject.Remove("sub"); noSubject.Remove("sid");
        await Assert.ThrowsAsync<MoonSsoException>(() => verifier.ValidateAsync(Sign(noSubject)));
        var futureIat = Claims(); futureIat["iat"] = Now + 120;
        await Assert.ThrowsAsync<MoonSsoException>(() => verifier.ValidateAsync(Sign(futureIat)));
        var wrongAud = Claims(); wrongAud["aud"] = "other";
        await Assert.ThrowsAsync<MoonSsoException>(() => verifier.ValidateAsync(Sign(wrongAud)));
        var sidOnly = Claims(); sidOnly.Remove("sub");
        Assert.Null((await verifier.ValidateAsync(Sign(sidOnly))).Subject);
    }

    [Fact]
    public void DPoPProof_HasRequiredShapeAndVerifies()
    {
        using var key = DPoPKey.Generate();
        var proof = key.CreateProof("post", "https://sso.example.test/oauth/token?x=1", "nonce-1", _time.GetUtcNow());
        var jws = JwsToken.Parse(proof);
        Assert.Equal("dpop+jwt", jws.Typ);
        Assert.Equal("ES256", jws.Alg);
        var jwk = jws.Header.GetProperty("jwk");
        Assert.Equal(new[] { "kty", "crv", "x", "y" }, jwk.EnumerateObject().Select(p => p.Name).ToArray());
        Assert.Equal("POST", jws.Payload.GetProperty("htm").GetString());
        Assert.Equal("https://sso.example.test/oauth/token", jws.Payload.GetProperty("htu").GetString());
        Assert.Equal("nonce-1", jws.Payload.GetProperty("nonce").GetString());
        Assert.Equal(_time.GetUtcNow().ToUnixTimeSeconds(), jws.Payload.GetProperty("iat").GetInt64());
        Assert.False(string.IsNullOrEmpty(jws.Payload.GetProperty("jti").GetString()));
        var publicJwk = new JsonWebKey { Kty = "EC", Crv = "P-256", X = jwk.GetProperty("x").GetString(), Y = jwk.GetProperty("y").GetString() };
        Assert.True(JwsVerifier.Verify(jws, publicJwk));

        // RFC 7638 thumbprint is stable across export/import
        using var restored = DPoPKey.Import(key.Export());
        Assert.Equal(key.Thumbprint, restored.Thumbprint);
        Assert.Equal(43, key.Thumbprint.Length);
        Assert.NotEqual(JwsToken.Parse(key.CreateProof("POST", "https://a/b", null, _time.GetUtcNow())).Payload.GetProperty("jti").GetString(),
            JwsToken.Parse(key.CreateProof("POST", "https://a/b", null, _time.GetUtcNow())).Payload.GetProperty("jti").GetString());
    }

    [Fact]
    public void Rfc7638_ThumbprintVectorForEcKey()
    {
        // RFC 7638 §3.1 is RSA; use RFC 9449 / RFC 7517 example EC key and compare with a manual computation.
        var data = new DPoPKeyData
        {
            X = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            Y = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
            D = "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI",
        };
        using var key = DPoPKey.Import(data);
        var json = "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\",\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\"}";
        Assert.Equal(Base64Url.Encode(SHA256.HashData(Encoding.UTF8.GetBytes(json))), key.Thumbprint);
    }

    public void Dispose()
    {
        _rsa.Dispose();
        _ec.Dispose();
        _ec384.Dispose();
    }
}
