using System.Security.Cryptography;
using System.Text;
using MoonSso.Internal;

namespace MoonSso;

/// <summary>A PKCE verifier / S256 challenge pair (RFC 7636).</summary>
public sealed record PkceCodes(string CodeVerifier, string CodeChallenge)
{
    public string CodeChallengeMethod => "S256";
}

/// <summary>PKCE and random value helpers.</summary>
public static class Pkce
{
    /// <summary>Creates a fresh verifier (64 base64url characters from 48 random bytes) and its S256 challenge.</summary>
    public static PkceCodes Create()
    {
        var verifier = CreateCodeVerifier();
        return new PkceCodes(verifier, ComputeChallenge(verifier));
    }

    /// <summary>Random code verifier of 43–128 unreserved characters.</summary>
    /// <param name="randomBytes">32..96 random bytes; the encoded length is ceil(4n/3).</param>
    public static string CreateCodeVerifier(int randomBytes = 48)
    {
        if (randomBytes is < 32 or > 96)
        {
            throw new ArgumentOutOfRangeException(nameof(randomBytes), "Must be between 32 and 96 bytes (43–128 characters).");
        }
        return Base64Url.Random(randomBytes);
    }

    /// <summary>S256 challenge: base64url(SHA-256(ASCII(verifier))).</summary>
    public static string ComputeChallenge(string codeVerifier)
    {
        ArgumentNullException.ThrowIfNull(codeVerifier);
        if (codeVerifier.Length is < 43 or > 128)
        {
            throw new ArgumentException("code_verifier must be 43–128 characters.", nameof(codeVerifier));
        }
        foreach (var c in codeVerifier)
        {
            if (!(c is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '.' or '_' or '~'))
            {
                throw new ArgumentException("code_verifier contains invalid characters.", nameof(codeVerifier));
            }
        }
        return Base64Url.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier)));
    }

    /// <summary>Random base64url value with 256 bits of entropy, suitable for <c>state</c> and <c>nonce</c>.</summary>
    public static string RandomValue() => Base64Url.Random(32);
}
