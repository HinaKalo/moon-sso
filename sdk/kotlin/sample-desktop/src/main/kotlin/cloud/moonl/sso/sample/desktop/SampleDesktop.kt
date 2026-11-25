package cloud.moonl.sso.sample.desktop

import cloud.moonl.sso.AuthState
import cloud.moonl.sso.MoonSsoConfig
import cloud.moonl.sso.MoonSsoException
import cloud.moonl.sso.desktop.MoonSsoDesktop
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.swing.Swing
import java.awt.BorderLayout
import java.awt.FlowLayout
import java.awt.Font
import javax.swing.JButton
import javax.swing.JFrame
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTextArea
import javax.swing.SwingUtilities
import javax.swing.WindowConstants

/**
 * Minimal Swing app: browser login (loopback redirect), live profile via SSE, sign out.
 *
 * Configure with MOON_SSO_ISSUER (default: local testbed http://127.0.0.1:18601) and
 * MOON_SSO_CLIENT_ID (default: test-native).
 */
fun main() {
    val config = MoonSsoConfig(
        issuer = System.getenv("MOON_SSO_ISSUER") ?: "http://127.0.0.1:18601",
        clientId = System.getenv("MOON_SSO_CLIENT_ID") ?: "test-native",
        scopes = listOf("openid", "profile", "offline_access", "profile:write"),
    )
    val client = MoonSsoDesktop.create(config, "moon-sso-sample-desktop")
    val ui = CoroutineScope(SupervisorJob() + Dispatchers.Swing)

    SwingUtilities.invokeLater {
        val status = JLabel("正在读取登录状态…")
        val profile = JTextArea(8, 48).apply {
            isEditable = false
            font = Font(Font.MONOSPACED, Font.PLAIN, 13)
        }
        val login = JButton("浏览器登录")
        val logout = JButton("退出登录")

        login.addActionListener {
            login.isEnabled = false
            status.text = "已打开浏览器，请在浏览器中完成登录（5 分钟内有效）…"
            ui.launch {
                try {
                    MoonSsoDesktop.login(client)
                    client.account.getMe()
                } catch (e: MoonSsoException) {
                    status.text = "登录失败：${e.error} ${e.errorDescription.orEmpty()}"
                } finally {
                    login.isEnabled = true
                }
            }
        }
        logout.addActionListener { ui.launch { client.signOut() } }

        val buttons = JPanel(FlowLayout(FlowLayout.LEFT)).apply {
            add(login)
            add(logout)
        }
        val frame = JFrame("Moon SSO 桌面示例").apply {
            defaultCloseOperation = WindowConstants.EXIT_ON_CLOSE
            layout = BorderLayout(8, 8)
            add(status, BorderLayout.NORTH)
            add(JScrollPane(profile), BorderLayout.CENTER)
            add(buttons, BorderLayout.SOUTH)
            pack()
            setLocationRelativeTo(null)
        }
        frame.isVisible = true

        ui.launch {
            client.initialize()
            client.events.start()
        }
        ui.launch {
            client.authState.collect { s ->
                status.text = when (s) {
                    AuthState.Loading -> "正在读取登录状态…"
                    AuthState.SignedOut -> "未登录"
                    is AuthState.SignedIn -> "已登录（${s.subject}）"
                    is AuthState.SessionExpired -> "登录已失效，请重新登录"
                }
                logout.isEnabled = s is AuthState.SignedIn
            }
        }
        ui.launch {
            client.profile.collect { p ->
                profile.text = if (p == null) "" else buildString {
                    appendLine("用户名：${p.preferredUsername}")
                    appendLine("昵称：${p.nickname.orEmpty()}")
                    appendLine("头像：${p.picture ?: "（无）"}")
                    appendLine("资料版本：${p.profileVersion}")
                }
            }
        }
    }
}
