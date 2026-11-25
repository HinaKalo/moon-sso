package cloud.moonl.sso.desktop

import cloud.moonl.sso.MoonSsoClient
import cloud.moonl.sso.MoonSsoException
import cloud.moonl.sso.PendingAuthorization
import cloud.moonl.sso.TokenSet
import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import java.awt.Desktop
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.URI
import java.net.URLDecoder
import java.security.MessageDigest
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes

/** Opens the authorization URL for the user. */
public fun interface BrowserLauncher {
    public fun open(url: URI)

    public companion object {
        /**
         * System browser via `java.awt.Desktop`, then the OS opener (`rundll32`/`open`/`xdg-open`),
         * and as a last resort prints the URL to stderr for the user to open manually.
         */
        public val System: BrowserLauncher = BrowserLauncher { url ->
            if (!openWithDesktop(url) && !openWithCommand(url)) {
                java.lang.System.err.println("请在浏览器中打开以下地址完成登录：\n$url")
            }
        }

        private fun openWithDesktop(url: URI): Boolean = try {
            if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                Desktop.getDesktop().browse(url)
                true
            } else {
                false
            }
        } catch (_: Exception) {
            false
        }

        private fun openWithCommand(url: URI): Boolean = try {
            val cmd = when {
                Platform.isWindows -> listOf("rundll32", "url.dll,FileProtocolHandler", url.toString())
                Platform.isMac -> listOf("open", url.toString())
                else -> listOf("xdg-open", url.toString())
            }
            ProcessBuilder(cmd).start()
            true
        } catch (_: Exception) {
            false
        }
    }
}

/**
 * Browser login for desktop apps (RFC 8252): opens the system browser and receives the redirect on
 * a one-shot loopback listener `http://127.0.0.1:<random port>/callback`, answers the browser with a
 * “登录完成” page and exchanges the code (PKCE, state, iss and nonce are verified). Gives up after
 * [timeout] (5 minutes by default) with error `timeout`.
 */
public class DesktopLogin(
    private val client: MoonSsoClient,
    private val browser: BrowserLauncher = BrowserLauncher.System,
    private val timeout: Duration = 5.minutes,
) {
    /** Runs the whole flow and returns the new tokens. */
    public suspend fun login(
        scopes: List<String> = client.config.scopes,
        prompt: String? = null,
        loginHint: String? = null,
    ): TokenSet {
        val executor: ExecutorService = Executors.newSingleThreadExecutor { r -> Thread(r, "moon-sso-loopback").apply { isDaemon = true } }
        val server = withContext(Dispatchers.IO) {
            HttpServer.create(InetSocketAddress(InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)), 0), 0)
        }
        try {
            val redirectUri = "http://127.0.0.1:${server.address.port}/callback"
            val pending = client.createAuthorizationRequest(redirectUri, scopes, prompt, loginHint)
            val callback = CompletableDeferred<String>()
            server.createContext("/") { exchange -> handle(exchange, pending, callback) }
            server.executor = executor
            server.start()
            withContext(Dispatchers.IO) { browser.open(URI(pending.authorizationUrl)) }
            val callbackUri = try {
                withTimeout(timeout) { callback.await() }
            } catch (e: TimeoutCancellationException) {
                throw MoonSsoException(MoonSsoException.TIMEOUT, "no authorization response within ${timeout.inWholeSeconds} seconds")
            }
            return client.completeAuthorization(pending, callbackUri)
        } finally {
            server.stop(0)
            executor.shutdownNow()
        }
    }

    private fun handle(exchange: HttpExchange, pending: PendingAuthorization, callback: CompletableDeferred<String>) {
        val ex = exchange
        try {
            val uri = ex.requestURI
            if (ex.requestMethod != "GET" || uri.path != "/callback") {
                respond(ex, 404, page("未找到", "此地址只用于接收登录结果。"))
                return
            }
            val params = parseQuery(uri.rawQuery)
            val state = params["state"]
            // Requests without the right state (other pages poking the port) are ignored; keep waiting.
            if (state == null || !MessageDigest.isEqual(state.toByteArray(), pending.state.toByteArray()) || callback.isCompleted) {
                respond(ex, 400, page("无效的请求", "此请求不属于当前的登录流程。"))
                return
            }
            val error = params["error"]
            if (error != null) {
                respond(ex, 200, page("登录未完成", "登录没有完成（${escape(params["error_description"] ?: error)}）。请回到应用重试。"))
            } else {
                respond(ex, 200, page("登录完成", "登录完成，可以关闭此页面，回到应用继续。"))
            }
            callback.complete(pending.redirectUri + (uri.rawQuery?.let { "?$it" } ?: ""))
        } finally {
            ex.close()
        }
    }

    private fun respond(ex: HttpExchange, status: Int, html: String) {
        val body = html.toByteArray(Charsets.UTF_8)
        ex.responseHeaders.apply {
            set("Content-Type", "text/html; charset=utf-8")
            set("Cache-Control", "no-store")
            set("Referrer-Policy", "no-referrer")
            set("X-Content-Type-Options", "nosniff")
            set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
        }
        ex.sendResponseHeaders(status, body.size.toLong())
        ex.responseBody.use { it.write(body) }
    }

    private fun page(title: String, message: String) = """<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>$title · Moon SSO</title>
<style>body{font-family:system-ui,-apple-system,"Segoe UI","Microsoft YaHei",sans-serif;background:#f5f6f8;color:#1f2328;display:flex;min-height:100vh;margin:0;align-items:center;justify-content:center}
main{background:#fff;border-radius:12px;padding:32px 40px;box-shadow:0 2px 12px rgba(0,0,0,.08);max-width:420px;text-align:center}
h1{font-size:20px;margin:0 0 12px}p{margin:0;line-height:1.6;color:#57606a}</style></head>
<body><main><h1>$title</h1><p>$message</p></main></body></html>"""

    private fun escape(s: String) = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")

    private fun parseQuery(raw: String?): Map<String, String> {
        if (raw.isNullOrEmpty()) return emptyMap()
        val out = LinkedHashMap<String, String>()
        for (part in raw.split('&')) {
            if (part.isEmpty()) continue
            val k = URLDecoder.decode(part.substringBefore('='), "UTF-8")
            if (!out.containsKey(k)) out[k] = URLDecoder.decode(part.substringAfter('=', ""), "UTF-8")
        }
        return out
    }
}
