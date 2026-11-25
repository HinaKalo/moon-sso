package cloud.moonl.sso.desktop

import cloud.moonl.sso.storage.CrossProcessLock
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.runInterruptible
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.nio.channels.FileChannel
import java.nio.channels.FileLock
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.util.concurrent.ConcurrentHashMap

/**
 * Cross-process lock based on an OS file lock (`FileChannel.lock`, i.e. `LockFileEx` on Windows and
 * `fcntl` on Unix). The OS releases it automatically when a process dies. Within one JVM, holders of
 * the same path are serialized by a coroutine [Mutex] first, because a JVM cannot hold two
 * overlapping locks on one file.
 */
public class FileCrossProcessLock(path: Path) : CrossProcessLock {
    private val path: Path = path.toAbsolutePath().normalize()
    private val jvmMutex: Mutex = JVM_LOCKS.computeIfAbsent(
        if (Platform.isWindows) this.path.toString().lowercase() else this.path.toString(),
    ) { Mutex() }

    override suspend fun <T> withLock(block: suspend () -> T): T = jvmMutex.withLock {
        val (channel, lock) = acquire()
        try {
            block()
        } finally {
            withContext(NonCancellable + Dispatchers.IO) {
                try {
                    lock.release()
                } finally {
                    channel.close()
                }
            }
        }
    }

    private suspend fun acquire(): Pair<FileChannel, FileLock> = runInterruptible(Dispatchers.IO) {
        path.parent?.let { Files.createDirectories(it) }
        val channel = FileChannel.open(path, StandardOpenOption.CREATE, StandardOpenOption.WRITE)
        try {
            channel to channel.lock()
        } catch (e: Throwable) {
            channel.close()
            throw e
        }
    }

    private companion object {
        val JVM_LOCKS = ConcurrentHashMap<String, Mutex>()
    }
}
