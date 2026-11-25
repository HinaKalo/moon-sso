package cloud.moonl.sso

import cloud.moonl.sso.sse.SseEvent
import cloud.moonl.sso.sse.SseParser
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class SseParserTest {
    private fun parse(vararg chunks: String): Triple<List<SseEvent>, List<Long>, SseParser> {
        val events = ArrayList<SseEvent>()
        val retries = ArrayList<Long>()
        val p = SseParser({ events.add(it) }, { retries.add(it) })
        chunks.forEach(p::push)
        return Triple(events, retries, p)
    }

    @Test
    fun `parses the server's frames`() {
        val (events, retries, p) = parse(
            "retry: 4321\n\n",
            ": ping\n\n",
            "id: 42\nevent: user.updated\ndata: {\"type\":\"user.updated\"}\n\n",
            "event: resync\ndata: {}\n\n",
        )
        assertEquals(listOf(4321L), retries)
        assertEquals(2, events.size)
        assertEquals(SseEvent("42", "user.updated", "{\"type\":\"user.updated\"}"), events[0])
        // The last event id persists for later events without an id field.
        assertEquals(SseEvent("42", "resync", "{}"), events[1])
        assertEquals("42", p.lastEventId)
    }

    @Test
    fun `handles chunks split anywhere and all line endings`() {
        val stream = "id: 7\r\nevent: a\r\ndata: one\r\ndata:two\r\n\r\ndata: three\rdata:  four\r\r: c\n\ndata\n\n"
        for (split in 1 until stream.length) {
            val (events, _, _) = parse(stream.substring(0, split), stream.substring(split))
            assertEquals(
                listOf(
                    SseEvent("7", "a", "one\ntwo"),
                    SseEvent("7", "message", "three\n four"),
                    SseEvent("7", "message", ""),
                ),
                events,
                "split at $split",
            )
        }
    }

    @Test
    fun `ignores invalid retry, unknown fields and id with NUL`() {
        val (events, retries, p) = parse("retry: 12a\nretry\nfoo: bar\nid: a\u0000b\ndata: x\n\n")
        assertEquals(emptyList(), retries)
        assertNull(p.lastEventId)
        assertEquals(listOf(SseEvent(null, "message", "x")), events)
    }

    @Test
    fun `event without data is not dispatched but its id is kept`() {
        val (events, _, p) = parse("id: 99\nevent: nothing\n\n")
        assertEquals(emptyList(), events)
        assertEquals("99", p.lastEventId)
    }

    @Test
    fun `resetEvent drops a partial event after a disconnect`() {
        val events = ArrayList<SseEvent>()
        val p = SseParser({ events.add(it) })
        p.push("event: x\ndata: partial")
        p.resetEvent()
        p.push("data: whole\n\n")
        assertEquals(listOf(SseEvent(null, "message", "whole")), events)
    }
}
