using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using MoonSso.Internal;

namespace MoonSso;

/// <summary>The webhook request failed verification.</summary>
public sealed class WebhookVerificationException : Exception
{
    public WebhookVerificationException(string message)
        : base(message)
    {
    }
}

/// <summary>
/// Verifies Moon SSO webhooks (Standard Webhooks): <c>webhook-signature</c> holds one or more space separated
/// <c>v1,&lt;base64(HMAC-SHA256(key, "{id}.{timestamp}.{body}"))&gt;</c>, where key is the base64-decoded part of the
/// <c>whsec_</c> secret. Timestamps more than 5 minutes away from now are rejected; comparisons are constant time.
/// </summary>
public sealed class WebhookVerifier
{
    private const string Prefix = "whsec_";
    private readonly byte[] _key;
    private readonly TimeProvider _time;

    /// <param name="secret">The <c>whsec_...</c> secret from the developer center or registration response.</param>
    public WebhookVerifier(string secret, TimeProvider? timeProvider = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(secret);
        var raw = secret.StartsWith(Prefix, StringComparison.Ordinal) ? secret[Prefix.Length..] : secret;
        try
        {
            _key = Convert.FromBase64String(raw);
        }
        catch (FormatException ex)
        {
            throw new ArgumentException("Webhook secret is not valid base64.", nameof(secret), ex);
        }
        _time = timeProvider ?? TimeProvider.System;
    }

    /// <summary>Maximum allowed distance between the webhook timestamp and now (default 5 minutes).</summary>
    public TimeSpan Tolerance { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>Computes the <c>v1,...</c> signature for a payload.</summary>
    public string Sign(string webhookId, long timestamp, ReadOnlySpan<byte> body)
    {
        var prefix = Encoding.UTF8.GetBytes(webhookId + "." + timestamp.ToString(CultureInfo.InvariantCulture) + ".");
        var content = new byte[prefix.Length + body.Length];
        prefix.CopyTo(content, 0);
        body.CopyTo(content.AsSpan(prefix.Length));
        return "v1," + Convert.ToBase64String(HMACSHA256.HashData(_key, content));
    }

    /// <summary>Verifies the headers against the raw request body. Throws <see cref="WebhookVerificationException"/> on failure.</summary>
    public void Verify(string? webhookId, string? webhookTimestamp, string? webhookSignature, ReadOnlySpan<byte> body)
    {
        if (string.IsNullOrEmpty(webhookId) || string.IsNullOrEmpty(webhookTimestamp) || string.IsNullOrEmpty(webhookSignature))
        {
            throw new WebhookVerificationException("Missing webhook-id, webhook-timestamp or webhook-signature header.");
        }
        if (!long.TryParse(webhookTimestamp, NumberStyles.None, CultureInfo.InvariantCulture, out var ts))
        {
            throw new WebhookVerificationException("Invalid webhook-timestamp.");
        }
        var now = _time.GetUtcNow().ToUnixTimeSeconds();
        if (Math.Abs(now - ts) > (long)Tolerance.TotalSeconds)
        {
            throw new WebhookVerificationException("Webhook timestamp is outside the allowed tolerance.");
        }
        var expected = Encoding.ASCII.GetBytes(Sign(webhookId, ts, body));
        foreach (var candidate in webhookSignature.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            if (!candidate.StartsWith("v1,", StringComparison.Ordinal))
            {
                continue;
            }
            if (CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(candidate), expected))
            {
                return;
            }
        }
        throw new WebhookVerificationException("No matching webhook signature.");
    }

    /// <summary>Verifies a string body (UTF-8).</summary>
    public void Verify(string? webhookId, string? webhookTimestamp, string? webhookSignature, string body) =>
        Verify(webhookId, webhookTimestamp, webhookSignature, Encoding.UTF8.GetBytes(body ?? ""));

    /// <summary>Returns false instead of throwing.</summary>
    public bool TryVerify(string? webhookId, string? webhookTimestamp, string? webhookSignature, ReadOnlySpan<byte> body)
    {
        try
        {
            Verify(webhookId, webhookTimestamp, webhookSignature, body);
            return true;
        }
        catch (WebhookVerificationException)
        {
            return false;
        }
    }

    /// <summary>
    /// Verifies and parses a webhook delivery. <paramref name="headers"/> is looked up case-insensitively
    /// (e.g. pass <c>name =&gt; Request.Headers[name]</c> in ASP.NET Core).
    /// </summary>
    public ProfileEvent VerifyAndParse(Func<string, string?> headers, byte[] body)
    {
        ArgumentNullException.ThrowIfNull(headers);
        ArgumentNullException.ThrowIfNull(body);
        Verify(headers("webhook-id"), headers("webhook-timestamp"), headers("webhook-signature"), body);
        try
        {
            return JsonSerializer.Deserialize<ProfileEvent>(body, Json.Options) ?? throw new WebhookVerificationException("Empty event.");
        }
        catch (JsonException ex)
        {
            throw new WebhookVerificationException("Webhook body is not a valid event: " + ex.Message);
        }
    }
}
