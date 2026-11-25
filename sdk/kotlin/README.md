# Moon SSO Kotlin SDK（Android + 桌面 JVM）

Moon SSO（OAuth 2.x / OpenID Connect）的 Kotlin SDK。安卓和桌面（Windows / macOS / Linux）都是一等公民，行为遵循 `docs/sdk-spec.md`。

| 模块 | 产物 | 内容 |
|---|---|---|
| `:core` | `cloud.moonl.sso:moon-sso-core`（JAR） | discovery、PKCE、令牌管理（75% 寿命主动刷新、单飞刷新、跨进程锁接口、轮换原子持久化、重试规则、`SessionExpired`）、DPoP（P-256、服务端 nonce、`dpop_jkt`）、应用内登录 + OTP + 应用内注册、浏览器授权码流程、OkHttp Interceptor/Authenticator、账号 API、SSE 资料同步、ID Token / Access Token 校验、DCR |
| `:android` | `cloud.moonl.sso:moon-sso-android`（AAR） | Custom Tabs 登录 + 回调 Activity（进程被杀也能完成登录）、Keystore AES-GCM 加密存储、Keystore EC DPoP 密钥、随生命周期连接/断开 SSE |
| `:desktop` | `cloud.moonl.sso:moon-sso-desktop`（JAR） | 系统浏览器登录（`http://127.0.0.1:<随机端口>/callback` 回环监听，5 分钟超时）、Windows DPAPI / macOS 钥匙串 / Linux Secret Service 安全存储（不可用时退回 0600 文件并警告）、跨进程文件锁 |
| `:sample-desktop` | — | Swing 示例 |
| `:sample-android` | — | 安卓示例 App |

依赖：OkHttp 4.12、kotlinx-coroutines 1.10、kotlinx-serialization-json 1.9、nimbus-jose-jwt 10（只用于 JOSE）。安卓模块另依赖 `androidx.browser` 和 `androidx.lifecycle:lifecycle-process`，桌面模块依赖 JNA（DPAPI）。`minSdk 24`，JVM 11+。

## 引入依赖

制品发布在静态 Maven 仓库 `https://sso.moonl.cloud/sdk/maven`：

```kotlin
// settings.gradle.kts
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        maven("https://sso.moonl.cloud/sdk/maven")
    }
}

// 安卓 App 的 build.gradle.kts
dependencies {
    implementation("cloud.moonl.sso:moon-sso-android:1.0.0")
}

// 桌面应用的 build.gradle.kts
dependencies {
    implementation("cloud.moonl.sso:moon-sso-desktop:1.0.0")
}
```

两者都会传递引入 `moon-sso-core`。只需要协议层（例如自己实现存储）时，可以只依赖 `cloud.moonl.sso:moon-sso-core:1.0.0`。

## 安卓

### 1. 回调地址与 Manifest

在 Moon SSO 开发者中心为应用登记回调 `<applicationId>:/oauth2redirect`（反向域名 scheme），例如 `com.example.app:/oauth2redirect`。

SDK 的 AAR 已经声明了接收回调的 `MoonSsoRedirectActivity`，App 只需在 `build.gradle.kts` 里提供 scheme：

```kotlin
android {
    defaultConfig {
        applicationId = "com.example.app"
        manifestPlaceholders["moonSsoRedirectScheme"] = "com.example.app"
    }
}
```

合并后的 Manifest 等价于：

```xml
<activity
    android:name="cloud.moonl.sso.android.MoonSsoRedirectActivity"
    android:exported="true"
    android:noHistory="true"
    android:excludeFromRecents="true"
    android:theme="@android:style/Theme.Translucent.NoTitleBar">
    <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="com.example.app" />
    </intent-filter>
</activity>
```

发起登录的 Activity 建议设为 `android:launchMode="singleTop"`：回调 Activity 会用 `FLAG_ACTIVITY_CLEAR_TOP | FLAG_ACTIVITY_SINGLE_TOP` 把它带回前台并关掉 Custom Tab，App 在 `onNewIntent`（以及进程被杀后重建时的 `onCreate`）里完成登录。

令牌存放在 `cloud.moonl.sso.<name>` 这个 SharedPreferences 文件里，用 Keystore 中的 AES-256-GCM 密钥加密。请把它排除在备份之外（`android:allowBackup="false"` 或 data extraction rules）；即使被恢复到别的设备也无法解密，SDK 会把它当作未登录并删除。

### 2. 初始化

```kotlin
class App : Application() {
    lateinit var sso: MoonSsoAndroid

    override fun onCreate() {
        super.onCreate()
        sso = MoonSsoAndroid.create(
            this,
            MoonSsoConfig(
                issuer = "https://sso.moonl.cloud",
                clientId = "你的 client_id",
                scopes = listOf("openid", "profile", "offline_access", "profile:write"),
            ),
        )
        sso.bindEventsToLifecycle() // 前台时连接 SSE，进入后台断开；Last-Event-ID 保证不丢事件
    }
}
```

DPoP 默认开启，私钥是 Android Keystore 中不可导出的 P-256 密钥。

### 3. 浏览器登录（Custom Tabs）

```kotlin
class MainActivity : ComponentActivity() {
    private val sso get() = (application as App).sso

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        loginButton.setOnClickListener {
            lifecycleScope.launch { sso.startBrowserLogin(this@MainActivity) }
        }
        complete() // 进程在浏览器打开期间被杀，也能在这里完成
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        complete()
    }

    private fun complete() = lifecycleScope.launch {
        try {
            sso.completePendingLogin()?.let { /* 登录成功 */ }
        } catch (e: MoonSsoException) {
            // state / iss 不匹配、用户取消（access_denied）、网络错误等
        }
    }
}
```

PKCE verifier、state、nonce 会加密落盘，保证进程被杀后仍能完成授权。

### 4. 应用内登录（第一方应用）

```kotlin
try {
    sso.client.signInWithPassword(username, password)
} catch (e: OtpRequiredException) {
    val code = askUserForTotp()               // 让用户输入 6 位验证码
    sso.client.submitOtp(e.challenge, code)   // PKCE 参数与第一步相同，由 challenge 保存
} catch (e: PasswordChangeRequiredException) {
    openInBrowser(e.changeUrl)                // 管理员重置了密码，需要先在浏览器中修改
}

// 应用内注册：422 带 field（username / password / display_name），403 为 registration_closed
sso.client.register(username, password, displayName = "昵称")
```

## 桌面（Windows / macOS / Linux）

```kotlin
val client = MoonSsoDesktop.create(
    MoonSsoConfig(issuer = "https://sso.moonl.cloud", clientId = "你的 client_id"),
    appName = "my-app",          // 同名的多个进程共享同一份登录状态
)

runBlocking {
    client.initialize()
    if (client.tokens.value == null) {
        MoonSsoDesktop.login(client)   // 打开系统浏览器，回调 http://127.0.0.1:<随机端口>/callback
    }
    println(client.account.getMe().preferredUsername)
}
```

- 在开发者中心登记回调 `http://127.0.0.1/callback`，服务端对回环地址忽略端口。
- `DesktopLogin` 用 JDK 的 `HttpServer` 只监听 127.0.0.1，校验 state 后给浏览器回“登录完成，可以关闭此页面”，5 分钟内没有回调则抛出 `MoonSsoException(error = "timeout")`。浏览器通过 `java.awt.Desktop` 打开，失败时依次尝试 `rundll32` / `open` / `xdg-open`，最后把地址打印到 stderr。可以传入自定义 `BrowserLauncher`。
- 存储位置与方式：

| 系统 | 方式 | 文件 |
|---|---|---|
| Windows | DPAPI（CurrentUser）加密文件 | `%LOCALAPPDATA%\MoonSSO\<app>\session.dat` |
| macOS | AES-GCM 文件，密钥存登录钥匙串（`security`，密钥经 stdin 传入） | `~/Library/Application Support/MoonSSO/<app>/session.enc` |
| Linux | AES-GCM 文件，密钥存 Secret Service（`secret-tool`） | `$XDG_DATA_HOME/moon-sso/<app>/session.enc` |
| Linux（无 Secret Service） | 0600 权限的明文 JSON，并记录警告 | `$XDG_DATA_HOME/moon-sso/<app>/session.json` |

- 存储内容为 JSON：`refresh_token`、`access_token`、`expires_at`、`id_token`、`profile`、`dpop_key`（DPoP 私钥 JWK，退出登录后保留）。
- 刷新时持有 `session.lock` 文件锁（`FileChannel.lock`，进程退出由系统释放），拿到锁后重读存储；别的进程已经刷新过就直接使用。

## 通用 API

```kotlin
client.authState        // StateFlow<AuthState>：Loading / SignedOut / SignedIn / SessionExpired
client.sessionExpired   // SharedFlow：只有刷新返回 invalid_grant 才会触发
client.profile          // StateFlow<Profile?>：本地缓存的资料
client.profileChanges   // SharedFlow<Profile>：账号 API 或 SSE 引起的资料变化

client.accessToken()            // 用掉 75% 寿命时先刷新再返回
client.tokenManager.refresh()   // 强制刷新；并发调用只发一个请求

client.account.getMe()
client.account.updateProfile(displayName = "新昵称", expectedVersion = profile.profileVersion) // If-Match，冲突时 412
client.account.uploadAvatar(pngBytes, "image/png")   // ≤ 5 MB
client.account.deleteAvatar()
client.account.changePassword(current, new)          // 本设备保持登录，其他设备被登出

client.events.start()   // SSE：Authorization 头 + Last-Event-ID 续传，retry 与抖动重连
client.events.stop()

client.httpClient       // 已装好 Interceptor（附加令牌 + 主动刷新）和 Authenticator（401 时刷新一次并重放）
client.signOut()        // 清除本地令牌、吊销 refresh token（失败不影响退出）
client.endSessionUrl(postLogoutRedirectUri)          // 浏览器端 RP-initiated logout 地址
client.idTokenClaims()                               // 校验后的 ID Token claims
client.accessTokenVerifier.verify(token, audience)   // 资源服务器本地校验 at+jwt

DynamicClientRegistration(issuer).registerClient(initialAccessToken, ClientMetadata(...))
```

`MoonSsoClient.httpClient` 只把令牌发给 issuer 所在主机，以及 `MoonSsoConfig.trustedApiHosts` 里列出的 HTTPS 主机。

### 错误模型

所有操作抛出 `MoonSsoException`，字段为 `error`（OAuth 错误码，或 `network`、`invalid_response`、`login_required`、`timeout`、`state_mismatch`）、`errorDescription`、`httpStatus`、`field`（422 时）。子类：`OtpRequiredException`、`PasswordChangeRequiredException`、`SessionExpiredException`。网络错误、5xx、429 永远不会清除登录态（`isTransient == true`）。日志不包含任何令牌、授权码或密码，`TokenSet` 等对象的 `toString()` 也会隐去敏感值。

### 重试规则

- 刷新：网络错误、连接重置、502/503/504 时用新的 DPoP 证明重试一次；`invalid_client` 不重试；`invalid_grant` 视为会话失效。
- 授权码换令牌：授权码只能用一次，重放会让服务端吊销整个令牌族，所以只在请求肯定没有送达（连接失败、DNS 失败）或服务端返回 503 时重试。
- 应用内登录 / 注册：不做网络重试，只在 `use_dpop_nonce` 时带新 nonce 立即重试一次。
- SDK 自己的 OAuth 请求关闭了 OkHttp 的静默重连重试：静默重试会重放同一个 DPoP 证明（服务端按 jti 拒绝）或授权码。

## 构建与测试

需要 JDK 17+（已用 JDK 21 验证）和 Android SDK（`local.properties` 中的 `sdk.dir`，compileSdk 36）。

```bash
./gradlew build                              # 编译、单元测试、集成测试、AAR/JAR
./gradlew :android:assembleRelease :android:testReleaseUnitTest
./gradlew :sample-android:assembleDebug
./gradlew :sample-desktop:run                # 默认连接本地测试床，可用 MOON_SSO_ISSUER / MOON_SSO_CLIENT_ID 覆盖
./gradlew publishToBuildRepo                 # 发布到 build/repo（静态 Maven 目录结构）
```

集成测试连接测试床 `http://127.0.0.1:18601`（可用环境变量 `MOON_SSO_TESTBED` 覆盖），测试床不可达时自动跳过。会修改资料或密码的测试都使用 `POST /__test/users` 新建的随机用户。

安卓示例默认使用测试床客户端 `test-native`，`applicationId` 为 `com.example.test`（与其回调 `com.example.test:/oauth2redirect` 一致）。在真机或模拟器上先执行 `adb reverse tcp:18601 tcp:18601`，设备上的 127.0.0.1:18601 就能访问本机测试床。连接其他服务时用 `-PmoonSsoIssuer=... -PmoonSsoClientId=...`。

`publishToBuildRepo` 生成的 `build/repo` 目录可以原样上传到 `https://sso.moonl.cloud/sdk/maven`。
