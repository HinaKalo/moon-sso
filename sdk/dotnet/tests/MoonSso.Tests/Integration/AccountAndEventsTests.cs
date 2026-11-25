using System.IO.Compression;
using System.Threading.Channels;
using MoonSso;

namespace MoonSso.Tests.Integration;

[Trait("Category", "Integration")]
public class AccountAndEventsTests
{
    private static async Task<T> Next<T>(ChannelReader<T> reader, Func<T, bool> match, TimeSpan timeout)
    {
        using var cts = new CancellationTokenSource(timeout);
        while (true)
        {
            var item = await reader.ReadAsync(cts.Token);
            if (match(item))
            {
                return item;
            }
        }
    }

    [Fact]
    public async Task ProfileUpdate_AndLiveEvents()
    {
        await Testbed.EnsureReachableAsync();
        var (user, password) = await Testbed.CreateUserAsync();
        await using var client = Testbed.CreateClient("test-native");
        await client.LoginWithPasswordAsync(user, password);

        var profiles = Channel.CreateUnbounded<ProfileChangedEventArgs>();
        var events = Channel.CreateUnbounded<ProfileEvent>();
        var connected = new TaskCompletionSource();
        client.ProfileChanged += (_, e) => profiles.Writer.TryWrite(e);
        client.Events.EventReceived += (_, e) => events.Writer.TryWrite(e.Event);
        client.Events.Connected += (_, _) => connected.TrySetResult();
        client.StartEvents();
        await connected.Task.WaitAsync(TimeSpan.FromSeconds(15));
        Assert.True(client.Events.IsRunning);

        // 1) A change made elsewhere arrives over SSE.
        await Testbed.SetDisplayNameAsync(user, "外部修改");
        var external = await Next(profiles.Reader, p => p.Profile.Nickname == "外部修改", TimeSpan.FromSeconds(20));
        Assert.Equal("event", external.Source);
        var evt = await Next(events.Reader, e => e.Type == EventTypes.UserUpdated, TimeSpan.FromSeconds(5));
        Assert.Equal(client.CurrentProfile!.Sub, evt.Data!.Sub);
        Assert.Contains("display_name", evt.Data.Changed ?? Array.Empty<string>());
        Assert.False(string.IsNullOrEmpty(client.Events.LastEventId));

        // 2) A change through the account API updates the cache at once.
        var version = client.CurrentProfile.ProfileVersion;
        var updated = await client.UpdateProfileAsync(new ProfileUpdate { DisplayName = "接口修改", IfMatchVersion = version });
        Assert.Equal("接口修改", updated.Nickname);
        Assert.True(updated.ProfileVersion > version);
        var viaApi = await Next(profiles.Reader, p => p.Profile.Nickname == "接口修改", TimeSpan.FromSeconds(5));
        Assert.Equal("api", viaApi.Source);
        // Its SSE echo is received but not reported again as a change (same profile_version).
        await Next(events.Reader, e => e.Type == EventTypes.UserUpdated && e.Data!.ProfileVersion == updated.ProfileVersion, TimeSpan.FromSeconds(20));

        // 3) Optimistic concurrency.
        var conflict = await Assert.ThrowsAsync<MoonSsoException>(() => client.UpdateProfileAsync(new ProfileUpdate { DisplayName = "x", IfMatchVersion = version }));
        Assert.Equal(412, conflict.StatusCode);
        Assert.Equal(ErrorCodes.VersionConflict, conflict.Error);

        // 4) Resume with Last-Event-ID: events while disconnected are delivered after reconnecting.
        await client.StopEventsAsync();
        Assert.False(client.Events.IsRunning);
        await Testbed.SetDisplayNameAsync(user, "离线期间");
        connected = new TaskCompletionSource();
        client.StartEvents();
        var missed = await Next(profiles.Reader, p => p.Profile.Nickname == "离线期间", TimeSpan.FromSeconds(20));
        Assert.Equal("event", missed.Source);
        await client.StopEventsAsync();

        Assert.Equal("离线期间", (await client.GetMeAsync()).Nickname);
    }

    [Fact]
    public async Task Avatar_UploadAndDelete()
    {
        await Testbed.EnsureReachableAsync();
        var (user, password) = await Testbed.CreateUserAsync();
        await using var client = Testbed.CreateClient("test-native");
        await client.LoginWithPasswordAsync(user, password);

        var withAvatar = await client.UploadAvatarAsync(Png(32, 32), "image/png");
        Assert.False(string.IsNullOrEmpty(withAvatar.Picture));
        using (var img = await Testbed.Http.GetAsync(withAvatar.Picture))
        {
            Assert.True(img.IsSuccessStatusCode);
        }
        Assert.Equal(withAvatar.Picture, client.CurrentProfile!.Picture);

        var bad = await Assert.ThrowsAsync<MoonSsoException>(() => client.UploadAvatarAsync(new byte[] { 1, 2, 3, 4 }, "image/png"));
        Assert.Equal(422, bad.StatusCode);
        await Assert.ThrowsAsync<ArgumentException>(() => client.UploadAvatarAsync(new byte[5 * 1024 * 1024 + 1], "image/png"));

        var without = await client.DeleteAvatarAsync();
        Assert.Null(without.Picture);
        Assert.Null(client.CurrentProfile!.Picture);
    }

    [Fact]
    public async Task ChangePassword_KeepsThisDevice()
    {
        await Testbed.EnsureReachableAsync();
        var (user, password) = await Testbed.CreateUserAsync();
        await using var client = Testbed.CreateClient("test-native");
        await client.LoginWithPasswordAsync(user, password);
        await using var otherDevice = Testbed.CreateClient("test-native");
        await otherDevice.LoginWithPasswordAsync(user, password);
        var otherExpired = new TaskCompletionSource<bool>();
        otherDevice.SessionExpired += (_, _) => otherExpired.TrySetResult(true);

        var wrong = await Assert.ThrowsAsync<MoonSsoException>(() => client.ChangePasswordAsync("not-the-password", Testbed.RandomPassword()));
        Assert.Equal(422, wrong.StatusCode);
        Assert.Equal("current_password", wrong.Field);

        var newPassword = Testbed.RandomPassword();
        await client.ChangePasswordAsync(password, newPassword);

        // This device stays signed in; the other one is signed out.
        await client.RefreshAsync();
        Assert.True(client.IsSignedIn);
        await Assert.ThrowsAsync<SessionExpiredException>(() => otherDevice.RefreshAsync());
        Assert.True(await otherExpired.Task.WaitAsync(TimeSpan.FromSeconds(10)));

        await using var again = Testbed.CreateClient("test-native");
        await again.LoginWithPasswordAsync(user, newPassword);
        Assert.True(again.IsSignedIn);
    }

    [Fact]
    public async Task PasswordChangedElsewhere_EventEndsSessionOfOtherDevice()
    {
        await Testbed.EnsureReachableAsync();
        var (user, password) = await Testbed.CreateUserAsync();
        await using var listener = Testbed.CreateClient("test-native");
        await listener.LoginWithPasswordAsync(user, password);
        var expired = new TaskCompletionSource<bool>();
        var connected = new TaskCompletionSource();
        listener.SessionExpired += (_, _) => expired.TrySetResult(true);
        listener.Events.Connected += (_, _) => connected.TrySetResult();
        listener.StartEvents();
        await connected.Task.WaitAsync(TimeSpan.FromSeconds(15));

        await using var changer = Testbed.CreateClient("test-native");
        await changer.LoginWithPasswordAsync(user, password);
        await changer.ChangePasswordAsync(password, Testbed.RandomPassword());

        Assert.True(await expired.Task.WaitAsync(TimeSpan.FromSeconds(20)));
        Assert.False(listener.IsSignedIn);
        for (var i = 0; i < 50 && listener.Events.IsRunning; i++)
        {
            await Task.Delay(100);
        }
        Assert.False(listener.Events.IsRunning);
    }

    /// <summary>Minimal valid RGB PNG (BCL only).</summary>
    private static byte[] Png(int width, int height)
    {
        using var raw = new MemoryStream();
        for (var y = 0; y < height; y++)
        {
            raw.WriteByte(0); // filter: none
            for (var x = 0; x < width; x++)
            {
                raw.WriteByte((byte)(x * 8));
                raw.WriteByte((byte)(y * 8));
                raw.WriteByte(0x80);
            }
        }
        using var z = new MemoryStream();
        using (var zs = new ZLibStream(z, CompressionLevel.Optimal, leaveOpen: true))
        {
            raw.Position = 0;
            raw.CopyTo(zs);
        }
        using var png = new MemoryStream();
        png.Write(new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A });
        var ihdr = new byte[13];
        WriteBE(ihdr, 0, width);
        WriteBE(ihdr, 4, height);
        ihdr[8] = 8; // bit depth
        ihdr[9] = 2; // truecolor
        Chunk(png, "IHDR", ihdr);
        Chunk(png, "IDAT", z.ToArray());
        Chunk(png, "IEND", Array.Empty<byte>());
        return png.ToArray();
    }

    private static void Chunk(Stream s, string type, byte[] data)
    {
        var len = new byte[4];
        WriteBE(len, 0, data.Length);
        s.Write(len);
        var typeBytes = System.Text.Encoding.ASCII.GetBytes(type);
        s.Write(typeBytes);
        s.Write(data);
        var crc = Crc32(typeBytes.Concat(data).ToArray());
        var c = new byte[4];
        WriteBE(c, 0, unchecked((int)crc));
        s.Write(c);
    }

    private static void WriteBE(byte[] b, int o, int v)
    {
        b[o] = (byte)(v >> 24);
        b[o + 1] = (byte)(v >> 16);
        b[o + 2] = (byte)(v >> 8);
        b[o + 3] = (byte)v;
    }

    private static uint Crc32(byte[] data)
    {
        var crc = 0xFFFFFFFFu;
        foreach (var b in data)
        {
            crc ^= b;
            for (var k = 0; k < 8; k++)
            {
                crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xEDB88320u : crc >> 1;
            }
        }
        return ~crc;
    }
}
