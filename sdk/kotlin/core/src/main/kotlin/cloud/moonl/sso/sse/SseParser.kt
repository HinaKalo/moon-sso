package cloud.moonl.sso.sse

/** One dispatched server-sent event. */
public data class SseEvent(
    /** Value of the last `id:` field seen (the event's last-event-id), or null. */
    val id: String?,
    /** `event:` field, `message` when absent. */
    val type: String,
    /** `data:` lines joined with `\n`. */
    val data: String,
)

/**
 * Incremental parser for `text/event-stream` (WHATWG HTML §9.2.6). Feed it text in arbitrary chunks
 * with [push] or complete lines with [pushLine]; it handles CRLF, LF and CR line endings, comments,
 * fields without a colon, the single optional space after the colon, `retry:` and `id:`.
 */
public class SseParser(
    private val onEvent: (SseEvent) -> Unit,
    private val onRetry: (Long) -> Unit = {},
) {
    private val data = StringBuilder()
    private var hasData = false
    private var eventType: String? = null
    private val pending = StringBuilder()
    private var lastWasCR = false

    /** Last event ID buffer (persists across events, as the specification requires). */
    public var lastEventId: String? = null
        private set

    /** Feeds a chunk of text (may contain partial lines). */
    public fun push(chunk: String) {
        for (ch in chunk) {
            when {
                ch == '\n' && lastWasCR -> lastWasCR = false // second half of CRLF
                ch == '\n' || ch == '\r' -> {
                    lastWasCR = ch == '\r'
                    val line = pending.toString()
                    pending.setLength(0)
                    pushLine(line)
                }
                else -> {
                    lastWasCR = false
                    pending.append(ch)
                }
            }
        }
    }

    /** Feeds one complete line without its terminator. An empty line dispatches the event. */
    public fun pushLine(rawLine: String) {
        // A UTF-8 BOM may only appear at the very start of the stream.
        val line = if (rawLine.isNotEmpty() && rawLine[0] == '﻿') rawLine.substring(1) else rawLine
        if (line.isEmpty()) {
            dispatch()
            return
        }
        if (line[0] == ':') return // comment, e.g. ": ping"
        val colon = line.indexOf(':')
        val field: String
        var value: String
        if (colon >= 0) {
            field = line.substring(0, colon)
            value = line.substring(colon + 1)
            if (value.startsWith(' ')) value = value.substring(1)
        } else {
            field = line
            value = ""
        }
        when (field) {
            "event" -> eventType = value
            "data" -> {
                if (hasData) data.append('\n')
                data.append(value)
                hasData = true
            }
            "id" -> if (value.indexOf('\u0000') < 0) lastEventId = value
            "retry" -> if (value.isNotEmpty() && value.all { it in '0'..'9' }) value.toLongOrNull()?.let(onRetry)
            else -> Unit // unknown fields are ignored
        }
    }

    /** Clears a partially received event (call when the connection drops). */
    public fun resetEvent() {
        data.setLength(0)
        hasData = false
        eventType = null
        pending.setLength(0)
        lastWasCR = false
    }

    private fun dispatch() {
        if (!hasData) {
            eventType = null
            return
        }
        val event = SseEvent(lastEventId?.takeIf { it.isNotEmpty() }, eventType?.takeIf { it.isNotEmpty() } ?: "message", data.toString())
        data.setLength(0)
        hasData = false
        eventType = null
        onEvent(event)
    }
}
