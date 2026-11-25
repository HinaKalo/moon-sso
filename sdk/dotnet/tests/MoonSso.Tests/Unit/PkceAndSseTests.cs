using MoonSso;

namespace MoonSso.Tests.Unit;

public class PkceTests
{
    [Fact]
    public void Rfc7636_AppendixB_Vector()
    {
        Assert.Equal("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", Pkce.ComputeChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"));
    }

    [Fact]
    public void Create_ProducesValidVerifierAndChallenge()
    {
        var seen = new HashSet<string>();
        for (var i = 0; i < 50; i++)
        {
            var p = Pkce.Create();
            Assert.InRange(p.CodeVerifier.Length, 43, 128);
            Assert.Matches("^[A-Za-z0-9_-]+$", p.CodeVerifier);
            Assert.Equal(Pkce.ComputeChallenge(p.CodeVerifier), p.CodeChallenge);
            Assert.Equal(43, p.CodeChallenge.Length);
            Assert.Equal("S256", p.CodeChallengeMethod);
            Assert.True(seen.Add(p.CodeVerifier));
        }
    }

    [Theory]
    [InlineData(32, 43)]
    [InlineData(96, 128)]
    public void CreateCodeVerifier_LengthBounds(int bytes, int expectedLength)
    {
        Assert.Equal(expectedLength, Pkce.CreateCodeVerifier(bytes).Length);
    }

    [Fact]
    public void ComputeChallenge_RejectsInvalidVerifiers()
    {
        Assert.Throws<ArgumentException>(() => Pkce.ComputeChallenge("short"));
        Assert.Throws<ArgumentException>(() => Pkce.ComputeChallenge(new string('a', 129)));
        Assert.Throws<ArgumentException>(() => Pkce.ComputeChallenge(new string('a', 42) + "+"));
        Assert.Throws<ArgumentOutOfRangeException>(() => Pkce.CreateCodeVerifier(16));
    }

    [Fact]
    public void RandomValue_Has256Bits()
    {
        var v = Pkce.RandomValue();
        Assert.Equal(43, v.Length);
        Assert.NotEqual(v, Pkce.RandomValue());
    }

    [Fact]
    public void QueryString_RoundTrip()
    {
        var q = QueryString.Build(new[] { new KeyValuePair<string, string>("redirect_uri", "http://127.0.0.1:1234/callback"), new("scope", "openid profile") });
        Assert.Equal("redirect_uri=http%3A%2F%2F127.0.0.1%3A1234%2Fcallback&scope=openid%20profile", q);
        var parsed = QueryString.Parse("?" + q + "&a=b+c&a=ignored&flag");
        Assert.Equal("http://127.0.0.1:1234/callback", parsed["redirect_uri"]);
        Assert.Equal("openid profile", parsed["scope"]);
        Assert.Equal("b c", parsed["a"]);
        Assert.Equal("", parsed["flag"]);
    }
}

public class SseParserTests
{
    private static List<SseEvent> Feed(SseParser p, string text)
    {
        var events = new List<SseEvent>();
        foreach (var line in text.Replace("\r\n", "\n").Split('\n'))
        {
            var e = p.ProcessLine(line);
            if (e is not null)
            {
                events.Add(e);
            }
        }
        return events;
    }

    [Fact]
    public void ParsesServerFrames()
    {
        var p = new SseParser();
        var events = Feed(p, "retry: 4321\n\n: ping\n\nid: 42\nevent: user.updated\ndata: {\"id\":\"evt_42\",\"seq\":42}\n\nevent: token_expired\ndata: {}\n\n");
        Assert.Equal(4321, p.RetryMilliseconds);
        Assert.Equal(2, events.Count);
        Assert.Equal(new SseEvent("42", "user.updated", "{\"id\":\"evt_42\",\"seq\":42}"), events[0]);
        Assert.Equal("token_expired", events[1].Event);
        Assert.Equal("{}", events[1].Data);
        Assert.Equal("42", events[1].Id); // last event id persists
        Assert.Equal("42", p.LastEventId);
    }

    [Fact]
    public void MultiLineDataAndFieldSyntax()
    {
        var p = new SseParser();
        var events = Feed(p, "data:first\ndata:  second\ndata\nunknown: x\n\n");
        Assert.Single(events);
        Assert.Equal("message", events[0].Event);
        Assert.Equal("first\n second\n", events[0].Data);
    }

    [Fact]
    public void IgnoresInvalidRetryAndNulId()
    {
        var p = new SseParser();
        Feed(p, "retry: 12a\nid: a\0b\ndata: x\n\n");
        Assert.Null(p.RetryMilliseconds);
        Assert.Null(p.LastEventId);
    }

    [Fact]
    public void EventWithoutDataIsNotDispatched_AndResetDropsPartialEvent()
    {
        var p = new SseParser();
        Assert.Empty(Feed(p, "event: user.updated\n\n"));
        p.ProcessLine("data: partial");
        p.Reset();
        Assert.Empty(Feed(p, "\n"));
    }

    [Fact]
    public void Backoff_UsesRetryWithJitterAndCaps()
    {
        for (var i = 0; i < 20; i++)
        {
            var d = MoonSsoEventStream.Backoff(4000, 1);
            Assert.InRange(d.TotalMilliseconds, 4000, 5000);
            var noRetry = MoonSsoEventStream.Backoff(null, 0);
            Assert.InRange(noRetry.TotalMilliseconds, 3000, 9000);
            var capped = MoonSsoEventStream.Backoff(8000, 10);
            Assert.InRange(capped.TotalMilliseconds, 60000, 61000);
        }
        Assert.InRange(MoonSsoEventStream.Backoff(1000, 3).TotalMilliseconds, 4000, 5000);
    }
}

public class WebhookTests
{
    private const string Secret = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
    private const string Id = "msg_p5jXN8AQM9LWM0D4loKWxJek";
    private const long Timestamp = 1614265330;
    private const string Body = "{\"test\": 2432232314}";
    private const string Expected = "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=";

    private static WebhookVerifier Verifier(long now = Timestamp) => new(Secret, new FixedTime(DateTimeOffset.FromUnixTimeSeconds(now)));

    [Fact]
    public void SpecTestVector_Signs()
    {
        Assert.Equal(Expected, Verifier().Sign(Id, Timestamp, System.Text.Encoding.UTF8.GetBytes(Body)));
    }

    [Fact]
    public void SpecTestVector_Verifies()
    {
        Verifier().Verify(Id, Timestamp.ToString(), Expected, Body);
        Verifier(Timestamp + 299).Verify(Id, Timestamp.ToString(), "v1,bogus " + Expected, Body);
    }

    [Fact]
    public void RejectsTamperingAndOldTimestamps()
    {
        Assert.Throws<WebhookVerificationException>(() => Verifier().Verify(Id, Timestamp.ToString(), Expected, Body + " "));
        Assert.Throws<WebhookVerificationException>(() => Verifier().Verify("msg_other", Timestamp.ToString(), Expected, Body));
        Assert.Throws<WebhookVerificationException>(() => Verifier(Timestamp + 301).Verify(Id, Timestamp.ToString(), Expected, Body));
        Assert.Throws<WebhookVerificationException>(() => Verifier(Timestamp - 301).Verify(Id, Timestamp.ToString(), Expected, Body));
        Assert.Throws<WebhookVerificationException>(() => Verifier().Verify(Id, Timestamp.ToString(), "v2," + Expected[3..], Body));
        Assert.Throws<WebhookVerificationException>(() => Verifier().Verify(Id, "abc", Expected, Body));
        Assert.Throws<WebhookVerificationException>(() => Verifier().Verify(Id, Timestamp.ToString(), null, Body));
        Assert.False(Verifier().TryVerify(Id, Timestamp.ToString(), "v1,AAAA", System.Text.Encoding.UTF8.GetBytes(Body)));
    }

    [Fact]
    public void VerifyAndParse_ReadsEvent()
    {
        var body = "{\"id\":\"evt_7\",\"seq\":7,\"type\":\"user.updated\",\"occurred_at\":\"2026-01-02T03:04:05Z\",\"data\":{\"sub\":\"u1\",\"status\":\"active\",\"name\":\"N\",\"picture\":null,\"profile_version\":3,\"updated_at\":1700000000,\"changed\":[\"name\"]}}";
        var bytes = System.Text.Encoding.UTF8.GetBytes(body);
        var v = Verifier();
        var sig = v.Sign("evt_7", Timestamp, bytes);
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Webhook-Id"] = "evt_7",
            ["Webhook-Timestamp"] = Timestamp.ToString(),
            ["Webhook-Signature"] = sig,
        };
        var evt = v.VerifyAndParse(n => headers.TryGetValue(n, out var x) ? x : null, bytes);
        Assert.Equal("user.updated", evt.Type);
        Assert.Equal(7, evt.Seq);
        Assert.Equal(3, evt.Data!.ProfileVersion);
        Assert.Equal(new[] { "name" }, evt.Data.Changed);
        Assert.Null(evt.Data.Picture);
    }
}

internal sealed class FixedTime : TimeProvider
{
    private DateTimeOffset _now;

    public FixedTime(DateTimeOffset now) => _now = now;

    public override DateTimeOffset GetUtcNow() => _now;

    public void Advance(TimeSpan by) => _now += by;
}
