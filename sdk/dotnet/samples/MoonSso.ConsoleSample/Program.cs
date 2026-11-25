// Moon SSO console sample: system-browser login, profile, live events.
//
//   dotnet run --project samples/MoonSso.ConsoleSample -- [--issuer URL] [--client-id ID] [--app-id ID] [--logout]
//
// Defaults target the local testbed (http://127.0.0.1:18601, client "test-native").

using MoonSso;
using MoonSso.Desktop;

var issuer = Arg("--issuer") ?? Environment.GetEnvironmentVariable("MOON_SSO_ISSUER") ?? "http://127.0.0.1:18601";
var clientId = Arg("--client-id") ?? Environment.GetEnvironmentVariable("MOON_SSO_CLIENT_ID") ?? "test-native";
var appId = Arg("--app-id") ?? "moonsso.consolesample";

await using var sso = MoonSsoDesktop.CreateClient(issuer, clientId, appId, o =>
{
    o.Scope = "openid profile offline_access profile:write";
    o.Logger = (level, message) =>
    {
        if (level >= MoonSsoLogLevel.Information)
        {
            Console.Error.WriteLine($"[{level}] {message}");
        }
    };
});

if (args.Contains("--logout"))
{
    await sso.InitializeAsync();
    await sso.LogoutAsync();
    Console.WriteLine("已退出登录。");
    return 0;
}

using var quit = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    quit.Cancel();
};

sso.SessionExpired += (_, e) =>
{
    Console.WriteLine($"登录已失效：{e.Reason}。请重新运行以登录。");
    quit.Cancel();
};
sso.ProfileChanged += (_, e) => Console.WriteLine($"资料已更新（{e.Source}）：{Describe(e.Profile)}");

try
{
    if (await sso.InitializeAsync(quit.Token))
    {
        Console.WriteLine("已从安全存储恢复登录状态。");
    }
    else
    {
        Console.WriteLine("正在打开浏览器登录……（5 分钟内完成）");
        await sso.LoginWithBrowserAsync(cancellationToken: quit.Token);
        Console.WriteLine("登录成功。");
    }

    var me = await sso.GetMeAsync(quit.Token);
    Console.WriteLine($"当前用户：{Describe(me)}");

    sso.Events.Connected += (_, _) => Console.WriteLine("已连接资料事件流，按 Ctrl+C 退出。");
    sso.Events.EventReceived += (_, e) => Console.WriteLine($"收到事件 {e.Event.Type} (#{e.Event.Seq})");
    sso.Events.Disconnected += (_, e) => Console.Error.WriteLine(e.RetryIn is { } d
        ? $"事件流断开（{(e.Error as MoonSsoException)?.Error ?? e.Error.GetType().Name}），{d.TotalSeconds:0} 秒后重连。"
        : "事件流已停止。");
    sso.StartEvents();

    await Task.Delay(Timeout.Infinite, quit.Token);
}
catch (OperationCanceledException) when (quit.IsCancellationRequested)
{
}
catch (TimeoutException)
{
    Console.Error.WriteLine("登录超时。");
    return 2;
}
catch (MoonSsoException ex)
{
    Console.Error.WriteLine($"错误：{ex.Error} {ex.ErrorDescription}");
    return 1;
}
finally
{
    await sso.StopEventsAsync();
}
return 0;

static string Describe(UserProfile p) =>
    $"{p.Name ?? p.PreferredUsername} (@{p.PreferredUsername}, sub={p.Sub}, v{p.ProfileVersion}){(p.Picture is null ? "" : " 头像=" + p.Picture)}";

string? Arg(string name)
{
    var i = Array.IndexOf(args, name);
    return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
}
