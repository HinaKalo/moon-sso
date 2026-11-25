package cloud.moonl.sso.desktop

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.io.TempDir
import java.io.File
import java.nio.channels.FileChannel
import java.nio.file.Path
import java.nio.file.Paths
import java.nio.file.StandardOpenOption
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Holds an OS file lock in a separate JVM: `LockHolder <path> <millis>`. */
object LockHolder {
    @JvmStatic
    fun main(args: Array<String>) {
        FileChannel.open(Paths.get(args[0]), StandardOpenOption.CREATE, StandardOpenOption.WRITE).use { ch ->
            ch.lock().use {
                println("locked")
                System.out.flush()
                Thread.sleep(args[1].toLong())
            }
        }
    }
}

class FileCrossProcessLockTest {
    @TempDir
    lateinit var dir: Path

    @Test
    fun `holders in one JVM are serialized`() = runBlocking {
        val inside = AtomicInteger()
        val maxInside = AtomicInteger()
        val locks = List(4) { FileCrossProcessLock(dir.resolve("a.lock")) }
        (0 until 40).map { i ->
            async(Dispatchers.Default) {
                locks[i % locks.size].withLock {
                    val n = inside.incrementAndGet()
                    maxInside.accumulateAndGet(n) { a, b -> maxOf(a, b) }
                    delay(2)
                    inside.decrementAndGet()
                }
            }
        }.awaitAll()
        assertEquals(1, maxInside.get())
    }

    @Test
    fun `lock held by another process blocks until it is released`() = runBlocking {
        val cp = System.getProperty("moonsso.testClasspath")
        assumeTrue(cp != null, "test classpath not provided")
        val lockFile = dir.resolve("b.lock")
        val java = Paths.get(System.getProperty("java.home"), "bin", if (Platform.isWindows) "java.exe" else "java").toString()
        val child = ProcessBuilder(java, "-cp", cp, LockHolder::class.java.name, lockFile.toString(), "1500")
            .redirectError(ProcessBuilder.Redirect.INHERIT)
            .start()
        try {
            val line = child.inputStream.bufferedReader().readLine()
            assertEquals("locked", line)
            val start = System.nanoTime()
            FileCrossProcessLock(lockFile).withLock { }
            val waitedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start)
            assertTrue(waitedMs >= 700, "acquired after only $waitedMs ms while another process held the lock")
        } finally {
            child.waitFor(10, TimeUnit.SECONDS)
            child.destroyForcibly()
        }
        assertTrue(File(lockFile.toString()).exists())
    }
}
