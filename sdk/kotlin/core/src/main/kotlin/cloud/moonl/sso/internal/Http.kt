package cloud.moonl.sso.internal

import cloud.moonl.sso.MoonSsoException
import cloud.moonl.sso.MoonSsoIOException
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import okhttp3.Call
import okhttp3.Callback
import okhttp3.Headers
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import java.io.IOException
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

internal val SdkJson: Json = Json {
    ignoreUnknownKeys = true
    explicitNulls = false
    encodeDefaults = true
    isLenient = false
}

/** Fully read HTTP response (bodies of SDK endpoints are small). */
internal class HttpResult(val code: Int, val headers: Headers, val body: String) {
    val isSuccessful: Boolean get() = code in 200..299

    fun json(): JsonObject? = try {
        SdkJson.parseToJsonElement(body) as? JsonObject
    } catch (_: Exception) {
        null
    }

    fun string(obj: JsonObject?, key: String): String? = (obj?.get(key) as? JsonPrimitive)?.contentOrNull
}

internal const val MAX_BODY_BYTES: Long = 2L * 1024 * 1024

/** Executes the call asynchronously and reads the whole body. Throws [IOException] on transport failure. */
internal suspend fun Call.awaitResult(): HttpResult = suspendCancellableCoroutine { cont ->
    cont.invokeOnCancellation { cancel() }
    enqueue(object : Callback {
        override fun onFailure(call: Call, e: IOException) {
            if (cont.isActive) cont.resumeWithException(e)
        }

        override fun onResponse(call: Call, response: Response) {
            val result = try {
                response.use { HttpResult(it.code, it.headers, it.peekBody(MAX_BODY_BYTES).string()) }
            } catch (e: IOException) {
                if (cont.isActive) cont.resumeWithException(e)
                return
            }
            if (cont.isActive) cont.resume(result)
        }
    })
}

/** Like [awaitResult] but maps transport failures to [MoonSsoException] (`network`). */
internal suspend fun OkHttpClient.send(request: Request): HttpResult = try {
    newCall(request).awaitResult()
} catch (e: MoonSsoIOException) {
    throw e.error
} catch (e: IOException) {
    throw networkError(e)
}

internal fun networkError(e: IOException): MoonSsoException =
    MoonSsoException(MoonSsoException.NETWORK, e.javaClass.simpleName + (e.message?.let { ": $it" } ?: ""), null, null, e)

/** Builds the SDK error from an error response. */
internal fun HttpResult.toError(): MoonSsoException {
    val obj = json()
    val error = string(obj, "error")
    return if (error != null) {
        MoonSsoException(error, string(obj, "error_description"), code, string(obj, "field"))
    } else {
        MoonSsoException(MoonSsoException.INVALID_RESPONSE, "unexpected HTTP $code response", code)
    }
}

internal fun HttpResult.requireSuccess(): HttpResult = if (isSuccessful) this else throw toError()

/** Adds the SDK User-Agent to every request. */
internal class UserAgentInterceptor(private val userAgent: String) : Interceptor {
    override fun intercept(chain: Interceptor.Chain): Response =
        chain.proceed(chain.request().newBuilder().header("User-Agent", userAgent).build())
}

internal inline fun <reified T> HttpResult.decode(): T = try {
    SdkJson.decodeFromString<T>(body)
} catch (e: Exception) {
    // No cause: parser messages quote the input, which may contain tokens or client secrets.
    throw MoonSsoException(MoonSsoException.INVALID_RESPONSE, "malformed JSON response (${e.javaClass.simpleName})", code)
}
