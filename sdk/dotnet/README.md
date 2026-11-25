# Moon SSO .NET SDK

Moon SSO（OAuth 2.x / OpenID Connect）的官方 .NET SDK，桌面应用优先支持。

| 包 | 目标框架 | 内容 |
|---|---|---|
| `MoonSso.Client` | net8.0、net10.0 | 发现文档、PKCE、DPoP、无感知续期（进程内 single-flight，支持跨进程锁）、第一方应用内登录（含两步验证）、应用内注册、账号 API、资料事件流（SSE）、ID Token / JWKS 校验、动态注册（DCR）、Webhook 与 Back-Channel Logout 校验。只依赖 BCL。 |
| `MoonSso.Desktop` | net8.0、net10.0 | 系统浏览器登录（回环地址回调）、系统安全存储（Windows DPAPI、macOS 钥匙串、Linux Secret Service）、跨进程刷新锁。适用于 WPF、WinForms、Avalonia 和控制台程序。 |

## 安装

包发布在 `https://sso.moonl.cloud/sdk/nuget/`。在解决方案根目录添加 `nuget.config`：

```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
    <add key="moon-sso" value="https://sso.moonl.cloud/sdk/nuget/" />
  </packageSources>
</configuration>
```

```shell
dotnet add package MoonSso.Desktop   # 桌面应用（会同时引用 MoonSso.Client）
dotnet add package MoonSso.Client    # 服务端、移动端或自行处理存储的场景
```

## 快速开始（控制台）

```csharp
using MoonSso;
using MoonSso.Desktop;

await using var sso = MoonSsoDesktop.CreateClient(
    issuer: "https://sso.moonl.cloud",
    clientId: "your-client-id",
    appId: "com.example.notes",                 // 决定本地存储位置，保持不变
    configure: o => o.Scope = "openid profile offline_access profile:write");

sso.SessionExpired += (_, e) => Console.WriteLine($"登录已失效：{e.Reason}");
sso.ProfileChanged += (_, e) => Console.WriteLine($"资料更新：{e.Profile.Name}");

if (!await sso.InitializeAsync())               // 从安全存储恢复会话
{
    await sso.LoginWithBrowserAsync();          // 打开系统浏览器，回调 http://127.0.0.1:<随机端口>/callback
}

var me = await sso.GetMeAsync();
Console.WriteLine($"你好，{me.Name}");

sso.StartEvents();                              // 实时接收资料变更
```

完整示例见 `samples/MoonSso.ConsoleSample`（默认连接本地测试床）：

```shell
dotnet run --project samples/MoonSso.ConsoleSample -- --issuer https://sso.moonl.cloud --client-id your-client-id
```

`MoonSsoDesktop.CreateClient` 会自动配置：

- **安全存储**：
  - Windows：用 DPAPI（CurrentUser）加密后写入 `%LOCALAPPDATA%\MoonSso\<appId>\session.dat`。
  - macOS：会话文件用 AES-256-GCM 加密，密钥放在钥匙串（通过 `/usr/bin/security`，密钥不会出现在命令行参数里）。
  - Linux：密钥放在 Secret Service（`secret-tool`）；不可用时退回权限为 0600 的 `~/.local/share/moon-sso/<appId>/session.json`，并通过 `Logger` 输出警告。
- **跨进程锁**：Windows 用命名 Mutex，其他系统用文件锁。同一个应用开多个实例时共享一份会话，刷新时先拿锁、再重读存储；如果别的进程已经刷新过，就直接采用它的结果，不会触发刷新令牌重用检测。
- **DPoP**：每个安装生成一把 P-256 密钥，随会话一起保存在安全存储里；退出登录后保留这把密钥。

## WPF

在 UI 线程创建客户端，并把 `SynchronizationContext.Current` 传给 `EventContext`，SDK 事件就会回到 UI 线程触发：

```csharp
public partial class App : Application
{
    public static MoonSsoClient Sso { get; private set; } = null!;

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        Sso = MoonSsoDesktop.CreateClient("https://sso.moonl.cloud", "your-client-id", "com.example.wpfapp", o =>
        {
            o.Scope = "openid profile offline_access profile:write";
            o.EventContext = SynchronizationContext.Current;   // DispatcherSynchronizationContext
        });
        Sso.SessionExpired += (_, _) => new LoginWindow().Show();
        Sso.ProfileChanged += (_, args) => ((MainViewModel)MainWindow.DataContext).Profile = args.Profile;

        if (!await Sso.InitializeAsync())
            new LoginWindow().Show();
        else
            Sso.StartEvents();
    }

    protected override async void OnExit(ExitEventArgs e)
    {
        await Sso.DisposeAsync();
        base.OnExit(e);
    }
}
```

登录按钮（浏览器登录）：

```csharp
private async void OnLoginClick(object sender, RoutedEventArgs e)
{
    try
    {
        await App.Sso.LoginWithBrowserAsync();
        App.Sso.StartEvents();
        Close();
    }
    catch (TimeoutException) { MessageBox.Show("登录超时，请重试。"); }
    catch (MoonSsoException ex) { MessageBox.Show($"登录失败：{ex.ErrorDescription ?? ex.Error}"); }
}
```

## WinForms

```csharp
internal static class Program
{
    [STAThread]
    private static void Main()
    {
        ApplicationConfiguration.Initialize();
        using var form = new MainForm();
        Application.Run(form);
    }
}

public partial class MainForm : Form
{
    private MoonSsoClient _sso = null!;

    protected override async void OnLoad(EventArgs e)
    {
        base.OnLoad(e);
        _sso = MoonSsoDesktop.CreateClient("https://sso.moonl.cloud", "your-client-id", "com.example.winforms", o =>
            o.EventContext = SynchronizationContext.Current);   // WindowsFormsSynchronizationContext
        _sso.ProfileChanged += (_, args) => userLabel.Text = args.Profile.Name;
        _sso.SessionExpired += (_, _) => loginButton.Visible = true;

        if (await _sso.InitializeAsync())
        {
            userLabel.Text = (await _sso.GetMeAsync()).Name;
            _sso.StartEvents();
        }
    }

    private async void loginButton_Click(object sender, EventArgs e)
    {
        await _sso.LoginWithBrowserAsync();
        loginButton.Visible = false;
        _sso.StartEvents();
    }

    protected override async void OnFormClosed(FormClosedEventArgs e)
    {
        await _sso.DisposeAsync();
        base.OnFormClosed(e);
    }
}
```

## Avalonia

```csharp
public partial class App : Application
{
    public static MoonSsoClient Sso { get; private set; } = null!;

    public override async void OnFrameworkInitializationCompleted()
    {
        Sso = MoonSsoDesktop.CreateClient("https://sso.moonl.cloud", "your-client-id", "com.example.avalonia", o =>
            o.EventContext = SynchronizationContext.Current);   // AvaloniaSynchronizationContext
        // 或者不设置 EventContext，在处理函数里用 Dispatcher.UIThread.Post(...)
        Sso.ProfileChanged += (_, e) => MainViewModel.Instance.Profile = e.Profile;
        Sso.SessionExpired += (_, _) => MainViewModel.Instance.ShowLogin();

        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            desktop.MainWindow = new MainWindow();
            desktop.ShutdownRequested += async (_, _) => await Sso.DisposeAsync();
        }
        base.OnFrameworkInitializationCompleted();

        if (await Sso.InitializeAsync())
            Sso.StartEvents();
    }
}
```

Avalonia 在 Windows、macOS、Linux 上都使用同一套代码：存储和跨进程锁会按平台自动选择。

## 应用内登录（第一方应用）

由管理员标记为“第一方 + 允许应用内登录”的应用，可以自己收集用户名和密码：

```csharp
try
{
    await sso.LoginWithPasswordAsync(username, password);
}
catch (OtpRequiredException otp)
{
    // 显示验证码输入框；SDK 已保存 PKCE verifier，必须用同一个 challenge 提交
    var code = await AskUserForOtpAsync();
    while (true)
    {
        try { await sso.SubmitOtpAsync(otp.Challenge, code); break; }
        catch (OtpRequiredException) { code = await AskUserForOtpAsync("验证码不正确"); }
    }
}
catch (PasswordChangeRequiredException pc)
{
    SystemBrowser.Open(pc.ChangeUrl!);   // 管理员重置了密码，需要先在浏览器里设置新密码
}
catch (MoonSsoException ex) when (ex.Error == "access_denied")
{
    ShowError("用户名或密码错误");
}
```

`auth_session` 有效期为 5 分钟，过期后 `SubmitOtpAsync` 会抛出 `invalid_grant`，需要从第一步重新开始。

## 应用内注册

```csharp
var info = await sso.GetRegistrationInfoAsync();   // 是否开放注册、口令最小长度、用户名规则
try
{
    await sso.RegisterAsync(new NativeRegistration(username, password, displayName: "小明"));
    // 注册成功后用户已登录
}
catch (MoonSsoException ex) when (ex.StatusCode == 422)
{
    ShowFieldError(ex.Field, ex.ErrorDescription);   // Field: username / password / display_name
}
catch (MoonSsoException ex) when (ex.Error == ErrorCodes.RegistrationClosed)
{
    ShowError("暂未开放注册");
}
```

## 账号 API

| 方法 | 所需 scope |
|---|---|
| `GetMeAsync()` | `profile` |
| `UpdateProfileAsync(new ProfileUpdate { DisplayName = "新昵称", IfMatchVersion = v })` | `profile:write` |
| `UploadAvatarAsync(bytes, "image/png")` / `DeleteAvatarAsync()` | `profile:write` |
| `ChangePasswordAsync(current, next, keepThisDevice: true)` | `password:write` |

调用成功后，SDK 会立即更新本地缓存的资料（`CurrentProfile`，并写入安全存储），然后触发 `ProfileChanged`。设置 `IfMatchVersion` 时，如果资料已被别处修改，会抛出 `MoonSsoException`，其中 `Error == "version_conflict"`、`StatusCode == 412`。

## 调用自己的 API

`MoonSsoAuthHandler` 会给请求附加 `Authorization: Bearer`。每次请求前，它会检查令牌是否已经用掉 75% 的寿命（覆盖电脑休眠后唤醒的情况），需要时先刷新；遇到 401 时强制刷新一次，再重放一次请求。只把它用在发往你自己 API 的 HttpClient 上：

```csharp
using var api = sso.CreateHttpClient(new Uri("https://api.example.com/"));
var orders = await api.GetFromJsonAsync<Order[]>("orders");

// 或者接入 IHttpClientFactory
services.AddHttpClient("api").AddHttpMessageHandler(sp => new MoonSsoAuthHandler(sp.GetRequiredService<MoonSsoClient>()));
```

## 资料事件（SSE）

```csharp
sso.Events.Connected += (_, _) => Console.WriteLine("已连接");
sso.Events.EventReceived += (_, e) => Console.WriteLine(e.Event.Type);
sso.Events.Disconnected += (_, e) => Console.WriteLine($"断开：{e.Error.Message}，{e.RetryIn} 后重连");
sso.StartEvents();
// ……
await sso.StopEventsAsync();
```

- 通过 `HttpClient` 流式读取，令牌只放在 `Authorization` 请求头里，不会出现在 URL 中。断线后按服务端 `retry:` 给出的间隔（没有时为 3–8 秒）加随机抖动重连，连续失败时指数退避，最长 60 秒。重连时带上 `Last-Event-ID`，不会漏掉事件。要跨重启续传，可以自己保存 `sso.Events.LastEventId`。
- 各类事件的处理：
  - `user.updated`：更新资料并触发 `ProfileChanged`；`profile_version` 比本地旧的事件会被丢弃。
  - `user.password_changed`、`user.disabled`、`user.deleted`、`consent.revoked`：先刷新一次。刷新返回 `invalid_grant` 时触发 `SessionExpired`；刷新成功说明是本设备自己改的密码，继续监听。
  - `resync`：重新获取 `/api/v1/me`。
  - `token_expired`：刷新令牌后立即重连。

## 令牌生命周期

- 客户端在令牌用掉 75% 寿命时，由后台定时器主动刷新（`RefreshThreshold`、`AutoRefresh` 可调）。另外，每次调用前也会检查一次。
- 同一会话同时只有一个刷新请求：进程内用 `SemaphoreSlim`，多个进程之间用 `IRefreshLock`。并发调用方等待同一个结果。
- 刷新得到的新 refresh token 会在持有锁的情况下立即原子写入 `ITokenStore`（临时文件 + 重命名）。
- 遇到网络错误或 502/503/504 时，用同样的参数重试一次，DPoP 证明重新生成；收到 `use_dpop_nonce` 时，用服务端给的 nonce 立即重试一次。
- **只有** `invalid_grant` 会结束会话并触发 `SessionExpired`。网络错误、5xx、429 都不会清除登录状态：如果当前令牌还没过期，`GetAccessTokenAsync` 会继续返回它。
- 授权码换令牌**不**做网络重试，因为服务端会把重放的授权码视为攻击，吊销它签发的所有令牌。

## 错误模型

所有错误都是 `MoonSsoException`，字段如下：

- `Error`：OAuth 错误码，或 `network`、`invalid_response`
- `ErrorDescription`
- `StatusCode`
- `Field`：422 校验错误时提供
- `IsTransient`：表示可以稍后重试

派生类型有 `SessionExpiredException`、`NotSignedInException`、`OtpRequiredException`、`PasswordChangeRequiredException`。日志和异常消息中不会出现令牌、密码或授权码。用 `MoonSsoOptions.Logger` 接收诊断日志。

## 自定义存储与锁

```csharp
var sso = new MoonSsoClient(new MoonSsoOptions
{
    Issuer = "https://sso.moonl.cloud",
    ClientId = "your-client-id",
    TokenStore = new DpapiTokenStore(@"D:\data\session.dat"),           // 或实现 ITokenStore
    RefreshLock = new NamedMutexRefreshLock("MyApp.MoonSso"),            // 或 FileRefreshLock / 自己实现 IRefreshLock
});
```

`ITokenStore` 的实现必须保证原子写入，SDK 只会在持有 `IRefreshLock` 时写入。

## 服务端 .NET 应用

### 校验 Webhook（Standard Webhooks）

```csharp
var verifier = new WebhookVerifier(builder.Configuration["MoonSso:WebhookSecret"]!);   // whsec_...

app.MapPost("/webhooks/moon-sso", async (HttpRequest req) =>
{
    using var ms = new MemoryStream();
    await req.Body.CopyToAsync(ms);
    try
    {
        var evt = verifier.VerifyAndParse(name => req.Headers[name].FirstOrDefault(), ms.ToArray());
        // 按 evt.Data.ProfileVersion 丢弃旧事件；用 webhook-id 去重
        return Results.Ok();
    }
    catch (WebhookVerificationException) { return Results.BadRequest(); }
});
```

### Back-Channel Logout

```csharp
var sso = new MoonSsoClient(new MoonSsoOptions { Issuer = "https://sso.moonl.cloud", ClientId = "web-app", ClientSecret = "..." });
var logout = new BackchannelLogoutVerifier(sso);

app.MapPost("/backchannel-logout", async (HttpRequest req) =>
{
    var form = await req.ReadFormAsync();
    try
    {
        var r = await logout.ValidateAsync(form["logout_token"].ToString());
        await sessions.EndAsync(r.Subject, r.SessionId);   // 你的会话存储
        return Results.Ok();
    }
    catch (MoonSsoException) { return Results.BadRequest(); }
});
```

### 资源服务器校验 access token

```csharp
var claims = await sso.Validator.ValidateAccessTokenAsync(bearerToken, expectedAudience: "your-client-id");
```

这一步会校验签名、`typ == at+jwt`、`iss`、`exp`、`nbf` 和 `aud`。

### 动态注册客户端（DCR）

```csharp
var reg = await sso.RegisterClientAsync(initialAccessToken, new ClientRegistrationRequest
{
    ClientName = "My App",
    RedirectUris = new[] { "http://127.0.0.1/callback" },
    ApplicationType = "native",
    TokenEndpointAuthMethod = "none",
});
// reg.ClientId、reg.ClientSecret、reg.RegistrationAccessToken、reg.Status（active / pending_approval）
```

## 构建、测试与打包

```shell
dotnet build MoonSso.slnx
dotnet test tests/MoonSso.Tests --filter "Category!=Integration"   # 单元测试
dotnet test tests/MoonSso.Tests --filter "Category=Integration"    # 需要本地测试床 http://127.0.0.1:18601
dotnet pack MoonSso.slnx -c Release                                # 输出到 artifacts/
```

测试床地址可以用环境变量 `MOON_SSO_TESTBED` 覆盖。集成测试会通过 `/__test/users` 创建随机用户，不会修改 alice 和 bob。
