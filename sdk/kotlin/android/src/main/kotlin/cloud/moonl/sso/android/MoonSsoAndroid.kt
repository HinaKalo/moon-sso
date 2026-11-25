package cloud.moonl.sso.android

import android.annotation.SuppressLint
import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Context
import android.net.Uri
import androidx.browser.customtabs.CustomTabsIntent
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import cloud.moonl.sso.MoonSsoClient
import cloud.moonl.sso.MoonSsoConfig
import cloud.moonl.sso.MoonSsoException
import cloud.moonl.sso.TokenSet
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import java.lang.ref.WeakReference
import java.util.concurrent.ConcurrentHashMap

/**
 * Android integration: Keystore-encrypted session storage, Keystore DPoP key, browser login with
 * Custom Tabs and the `<scheme>:/oauth2redirect` redirect activity, and lifecycle-aware profile events.
 *
 * Create one instance per client in `Application.onCreate` (or lazily) with [create].
 */
public class MoonSsoAndroid private constructor(
    private val appContext: Context,
    /** The platform-independent client (tokens, account API, events). */
    public val client: MoonSsoClient,
    /** Redirect URI registered for this client, `<applicationId>:/oauth2redirect` by default. */
    public val redirectUri: String,
    private val name: String,
) {
    private val pendingStore = PendingAuthStore(KeystoreSecureStorage.pendingAuthStorage(appContext, name, client.config.logger))
    private val _redirects = MutableSharedFlow<Unit>(replay = 0, extraBufferCapacity = 1)

    /** Emits when the redirect activity stored a callback for this client (process still alive). */
    public val redirects: SharedFlow<Unit> = _redirects.asSharedFlow()

    /** True while a browser login was started and not yet completed or cancelled. */
    public val hasPendingLogin: Boolean get() = pendingStore.load() != null

    /**
     * Starts a browser login in a Custom Tab. When the user finishes, [MoonSsoRedirectActivity]
     * brings [activity] back (`onNewIntent`/`onResume`), where the app calls [completePendingLogin].
     */
    public suspend fun startBrowserLogin(
        activity: Activity,
        scopes: List<String> = client.config.scopes,
        prompt: String? = null,
        loginHint: String? = null,
        customTabsIntent: CustomTabsIntent = CustomTabsIntent.Builder().setShowTitle(true).build(),
    ) {
        val pending = client.createAuthorizationRequest(redirectUri, scopes, prompt, loginHint)
        withContext(Dispatchers.IO) {
            pendingStore.save(PendingLoginRecord(pending, returnActivity = activity.componentName.className))
            registerName(appContext, name)
        }
        withContext(Dispatchers.Main) {
            try {
                customTabsIntent.launchUrl(activity, Uri.parse(pending.authorizationUrl))
            } catch (e: ActivityNotFoundException) {
                pendingStore.clear()
                throw MoonSsoException("no_browser", "no browser is installed to show the login page", null, null, e)
            }
        }
    }

    /**
     * Finishes a browser login whose redirect was received (also after the process was killed while
     * the browser was open). Returns null when no redirect has arrived yet.
     */
    public suspend fun completePendingLogin(): TokenSet? {
        val record = withContext(Dispatchers.IO) { pendingStore.load() } ?: return null
        val callback = record.callback ?: return null
        withContext(Dispatchers.IO) { pendingStore.clear() }
        return client.completeAuthorization(record.pending, callback)
    }

    /** Forgets a browser login that was abandoned. */
    public fun cancelPendingLogin(): Unit = pendingStore.clear()

    /**
     * Connects the profile event stream while [owner] is started and disconnects in the background
     * (Last-Event-ID resumes without losing events). Call on the main thread.
     */
    public fun bindEventsToLifecycle(owner: LifecycleOwner = ProcessLifecycleOwner.get()) {
        owner.lifecycle.addObserver(object : DefaultLifecycleObserver {
            override fun onStart(owner: LifecycleOwner) = client.events.start()

            override fun onStop(owner: LifecycleOwner) = client.events.stop()
        })
    }

    public companion object {
        private const val REGISTRY = "cloud.moonl.sso.registry"
        private const val NAMES = "names"
        private val instances = ConcurrentHashMap<String, WeakReference<MoonSsoAndroid>>()

        /** Default redirect URI for an application id: `<applicationId>:/oauth2redirect`. */
        public fun defaultRedirectUri(applicationId: String): String = "$applicationId:/oauth2redirect"

        /**
         * Creates the Android client.
         *
         * @param name separates the storage of several clients in one app (letters, digits, `._-`).
         * @param redirectUri must be registered for the client and match `moonSsoRedirectScheme`.
         */
        public fun create(
            context: Context,
            config: MoonSsoConfig,
            name: String = "default",
            redirectUri: String = defaultRedirectUri(context.packageName),
            httpClient: OkHttpClient? = null,
        ): MoonSsoAndroid {
            val app = context.applicationContext
            val storage = KeystoreSecureStorage.create(app, name, config.logger)
            val client = MoonSsoClient.Builder(config)
                .storage(storage)
                .dpopKeyProvider(AndroidKeystoreDpopKeyProvider("cloud.moonl.sso.$name.dpop"))
                .apply { httpClient?.let { httpClient(it) } }
                .build()
            return MoonSsoAndroid(app, client, redirectUri, name).also { instances[name] = WeakReference(it) }
        }

        internal fun pendingStores(context: Context): List<Pair<String, PendingAuthStore>> {
            val prefs = context.applicationContext.getSharedPreferences(REGISTRY, Context.MODE_PRIVATE)
            return prefs.getStringSet(NAMES, emptySet()).orEmpty().sorted().map { n ->
                n to PendingAuthStore(KeystoreSecureStorage.pendingAuthStorage(context, n, cloud.moonl.sso.MoonSsoLogger.Default))
            }
        }

        internal fun notifyRedirect(name: String) {
            instances[name]?.get()?._redirects?.tryEmit(Unit)
        }

        @SuppressLint("ApplySharedPref") // must be on disk before the browser opens (process may die)
        private fun registerName(context: Context, name: String) {
            val prefs = context.getSharedPreferences(REGISTRY, Context.MODE_PRIVATE)
            val names = prefs.getStringSet(NAMES, emptySet()).orEmpty()
            if (name !in names) prefs.edit().putStringSet(NAMES, names + name).commit()
        }
    }
}
