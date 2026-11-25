using System.Security.Cryptography;

namespace MoonSso.Internal;

/// <summary>base64url without padding (RFC 4648 §5), as used by JOSE and PKCE.</summary>
internal static class Base64Url
{
    public static string Encode(ReadOnlySpan<byte> data)
    {
        return Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    public static byte[] Decode(string value)
    {
        if (!TryDecode(value, out var bytes))
        {
            throw new FormatException("Invalid base64url value.");
        }
        return bytes;
    }

    public static bool TryDecode(string? value, out byte[] bytes)
    {
        bytes = Array.Empty<byte>();
        if (value is null)
        {
            return false;
        }
        foreach (var c in value)
        {
            if (!(c is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '_'))
            {
                return false;
            }
        }
        var s = value.Replace('-', '+').Replace('_', '/');
        switch (s.Length % 4)
        {
            case 2: s += "=="; break;
            case 3: s += "="; break;
            case 1: return false;
        }
        try
        {
            bytes = Convert.FromBase64String(s);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    /// <summary>Cryptographically random base64url string from <paramref name="byteCount"/> random bytes.</summary>
    public static string Random(int byteCount)
    {
        Span<byte> buf = stackalloc byte[byteCount];
        RandomNumberGenerator.Fill(buf);
        return Encode(buf);
    }
}
