using System.Text.Json;
using System.Text.Json.Serialization;

namespace MoonSso.Internal;

internal static class Json
{
    public static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.General)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        PropertyNameCaseInsensitive = false,
        NumberHandling = JsonNumberHandling.AllowReadingFromString,
    };

    public static string? GetString(this JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    public static long? GetInt64(this JsonElement e, string name)
    {
        if (e.ValueKind != JsonValueKind.Object || !e.TryGetProperty(name, out var v))
        {
            return null;
        }
        if (v.ValueKind == JsonValueKind.Number && v.TryGetInt64(out var l))
        {
            return l;
        }
        if (v.ValueKind == JsonValueKind.Number && v.TryGetDouble(out var d))
        {
            return (long)d;
        }
        return null;
    }

    public static T Deserialize<T>(JsonElement e)
    {
        try
        {
            return e.Deserialize<T>(Options) ?? throw new MoonSsoException(ErrorCodes.InvalidResponse, $"Empty {typeof(T).Name} response.");
        }
        catch (JsonException ex)
        {
            throw new MoonSsoException(ErrorCodes.InvalidResponse, $"Malformed {typeof(T).Name} response.", innerException: ex);
        }
    }
}
