package cloud.moonl.sso.sample

import android.app.Application
import cloud.moonl.sso.MoonSsoConfig
import cloud.moonl.sso.android.MoonSsoAndroid

class SampleApp : Application() {
    lateinit var sso: MoonSsoAndroid
        private set

    override fun onCreate() {
        super.onCreate()
        sso = MoonSsoAndroid.create(
            this,
            MoonSsoConfig(
                issuer = BuildConfig.MOON_SSO_ISSUER,
                clientId = BuildConfig.MOON_SSO_CLIENT_ID,
                scopes = listOf("openid", "profile", "offline_access", "profile:write"),
            ),
        )
        // Live profile events while the app is in the foreground.
        sso.bindEventsToLifecycle()
    }
}
