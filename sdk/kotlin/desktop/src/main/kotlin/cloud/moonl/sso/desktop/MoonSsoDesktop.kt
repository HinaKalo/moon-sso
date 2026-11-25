package cloud.moonl.sso.desktop

import cloud.moonl.sso.MoonSsoClient
import cloud.moonl.sso.MoonSsoConfig
import cloud.moonl.sso.TokenSet
import okhttp3.OkHttpClient
import java.nio.file.Path

/** Factory for desktop (JVM) applications. */
public object MoonSsoDesktop {
    /**
     * Creates a client whose session (tokens, profile, DPoP key) lives in the OS secure storage
     * (DPAPI / Keychain / Secret Service, 0600 file as fallback) and whose refreshes are serialized
     * across processes of the same app with a file lock.
     *
     * @param appName identifies the storage; processes using the same name share one session.
     * @param directory overrides the storage directory (tests, portable installs).
     */
    public fun create(
        config: MoonSsoConfig,
        appName: String,
        httpClient: OkHttpClient? = null,
        directory: Path? = null,
    ): MoonSsoClient {
        val storage = DesktopSecureStorage.forApp(appName, config.logger, directory)
        return MoonSsoClient.Builder(config)
            .storage(storage.storage)
            .crossProcessLock(FileCrossProcessLock(storage.lockFile))
            .apply { httpClient?.let { httpClient(it) } }
            .build()
    }

    /** Browser login with a loopback redirect (5-minute timeout); see [DesktopLogin]. */
    public suspend fun login(
        client: MoonSsoClient,
        browser: BrowserLauncher = BrowserLauncher.System,
        scopes: List<String> = client.config.scopes,
    ): TokenSet = DesktopLogin(client, browser).login(scopes)
}
