package cloud.moonl.sso.android

import android.app.Activity
import android.content.ComponentName
import android.content.Intent
import android.os.Bundle
import cloud.moonl.sso.MoonSsoLogger

/**
 * Receives `<scheme>:/oauth2redirect?code=...&state=...&iss=...` from the browser, stores it with
 * the pending login (encrypted, survives process death) and returns to the activity that started
 * the login, closing the Custom Tab (`FLAG_ACTIVITY_CLEAR_TOP`). That activity then calls
 * [MoonSsoAndroid.completePendingLogin].
 */
public class MoonSsoRedirectActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val uri = intent?.data?.toString()
        val record = if (uri != null) {
            MoonSsoAndroid.pendingStores(this).firstNotNullOfOrNull { (name, store) ->
                store.acceptCallback(uri, System.currentTimeMillis() / 1000)?.also { MoonSsoAndroid.notifyRedirect(name) }
            }
        } else {
            null
        }
        val target = record?.returnActivity?.let { Intent().setComponent(ComponentName(this, it)) }
            ?: packageManager.getLaunchIntentForPackage(packageName)
        if (record == null) {
            MoonSsoLogger.Default.log(MoonSsoLogger.Level.WARN, "ignoring a redirect that matches no pending Moon SSO login", null)
        }
        if (target != null) {
            target.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
            startActivity(target)
        }
        finish()
    }
}
