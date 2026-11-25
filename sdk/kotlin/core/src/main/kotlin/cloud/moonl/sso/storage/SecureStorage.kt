package cloud.moonl.sso.storage

/**
 * Platform secure storage holding one opaque string (the SDK's session JSON: tokens, profile and,
 * on desktop, the DPoP private key).
 *
 * Methods are blocking and are always invoked from an I/O dispatcher. [write] must be atomic
 * (readers see either the old or the new value) and durable when it returns, because rotated
 * refresh tokens invalidate their predecessors.
 */
public interface SecureStorage {
    /** Returns the stored value, or null when nothing is stored. */
    public fun read(): String?

    /** Atomically replaces the stored value. */
    public fun write(value: String)

    /** Removes the stored value. */
    public fun clear()
}

/** Non-persistent storage for tests and short-lived processes. */
public class InMemorySecureStorage(initial: String? = null) : SecureStorage {
    @Volatile
    private var value: String? = initial

    override fun read(): String? = value

    override fun write(value: String) {
        this.value = value
    }

    override fun clear() {
        value = null
    }
}

/**
 * Lock shared by all processes that use the same [SecureStorage]. The SDK takes it around every
 * read-modify-write of the storage, in particular around refreshes, and re-reads the storage after
 * acquiring it so that a refresh done by another process is adopted instead of repeated.
 */
public interface CrossProcessLock {
    public suspend fun <T> withLock(block: suspend () -> T): T
}

/** For storages that are private to one process. */
public object NoCrossProcessLock : CrossProcessLock {
    override suspend fun <T> withLock(block: suspend () -> T): T = block()
}
