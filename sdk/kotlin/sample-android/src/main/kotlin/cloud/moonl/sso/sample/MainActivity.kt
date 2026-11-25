package cloud.moonl.sso.sample

import android.app.AlertDialog
import android.content.Intent
import android.os.Bundle
import android.text.InputType
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import androidx.activity.ComponentActivity
import androidx.lifecycle.lifecycleScope
import cloud.moonl.sso.AuthState
import cloud.moonl.sso.MoonSsoException
import cloud.moonl.sso.OtpChallenge
import cloud.moonl.sso.OtpRequiredException
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {
    private val sso get() = (application as SampleApp).sso
    private lateinit var status: TextView
    private lateinit var profile: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val pad = (16 * resources.displayMetrics.density).toInt()
        status = TextView(this)
        profile = TextView(this)
        val username = EditText(this).apply { hint = "用户名" }
        val password = EditText(this).apply {
            hint = "密码"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        }
        val browserLogin = Button(this).apply { text = "浏览器登录（Custom Tabs）" }
        val passwordLogin = Button(this).apply { text = "账号密码登录（应用内）" }
        val logout = Button(this).apply { text = "退出登录" }

        setContentView(
            LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(pad, pad, pad, pad)
                listOf(status, username, password, passwordLogin, browserLogin, logout, profile).forEach {
                    addView(it, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))
                }
            },
        )

        browserLogin.setOnClickListener {
            lifecycleScope.launch { guarded { sso.startBrowserLogin(this@MainActivity) } }
        }
        passwordLogin.setOnClickListener {
            lifecycleScope.launch {
                guarded {
                    try {
                        sso.client.signInWithPassword(username.text.toString(), password.text.toString())
                        sso.client.account.getMe()
                    } catch (e: OtpRequiredException) {
                        askOtp(e.challenge)
                    }
                }
            }
        }
        logout.setOnClickListener { lifecycleScope.launch { sso.client.signOut() } }

        lifecycleScope.launch {
            sso.client.authState.collect { s ->
                status.text = when (s) {
                    AuthState.Loading -> "正在读取登录状态…"
                    AuthState.SignedOut -> "未登录"
                    is AuthState.SignedIn -> "已登录（${s.subject}）"
                    is AuthState.SessionExpired -> "登录已失效，请重新登录"
                }
            }
        }
        lifecycleScope.launch {
            sso.client.profile.collect { p ->
                profile.text = if (p == null) "" else "用户名：${p.preferredUsername}\n昵称：${p.nickname.orEmpty()}\n资料版本：${p.profileVersion}"
            }
        }
        lifecycleScope.launch { sso.client.initialize() }
        completeBrowserLogin()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        // MoonSsoRedirectActivity brings this activity back after the browser login.
        completeBrowserLogin()
    }

    private fun completeBrowserLogin() {
        lifecycleScope.launch {
            guarded {
                if (sso.completePendingLogin() != null) sso.client.account.getMe()
            }
        }
    }

    private fun askOtp(challenge: OtpChallenge) {
        val input = EditText(this).apply {
            hint = "6 位验证码"
            inputType = InputType.TYPE_CLASS_NUMBER
        }
        AlertDialog.Builder(this)
            .setTitle("两步验证")
            .setView(input)
            .setPositiveButton("确定") { _, _ ->
                lifecycleScope.launch {
                    guarded {
                        try {
                            sso.client.submitOtp(challenge, input.text.toString())
                            sso.client.account.getMe()
                        } catch (e: OtpRequiredException) {
                            askOtp(e.challenge)
                        }
                    }
                }
            }
            .setNegativeButton("取消", null)
            .show()
    }

    private suspend fun guarded(block: suspend () -> Unit) {
        try {
            block()
        } catch (e: MoonSsoException) {
            status.text = "出错了：${e.error} ${e.errorDescription.orEmpty()}"
        }
    }
}
