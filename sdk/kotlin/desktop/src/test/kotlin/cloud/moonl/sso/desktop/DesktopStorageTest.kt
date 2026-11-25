package cloud.moonl.sso.desktop

import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull

class DesktopStorageTest {
    @TempDir
    lateinit var dir: Path

    private val secret = """{"refresh_token":"rt-secret-value","access_token":"at","dpop_key":"{\"d\":\"x\"}"}"""

    private class MemoryKeys : SecretKeyStore {
        var key: ByteArray? = null
        override fun load(): ByteArray? = key?.copyOf()
        override fun save(key: ByteArray) {
            this.key = key.copyOf()
        }
        override fun delete() {
            key = null
        }
    }

    @Test
    fun `DPAPI storage round-trips and never writes plaintext`() {
        assumeTrue(Platform.isWindows, "Windows only")
        val file = dir.resolve("session.dat")
        val s = DpapiFileStorage(file, "test-app")
        assertNull(s.read())
        s.write(secret)
        assertEquals(secret, s.read())
        assertFalse(String(Files.readAllBytes(file), Charsets.ISO_8859_1).contains("rt-secret-value"))
        // Another app name (entropy) cannot decrypt it.
        assertFailsWith<Exception> { DpapiFileStorage(file, "other-app").read() }
        s.write("second")
        assertEquals("second", DpapiFileStorage(file, "test-app").read())
        s.clear()
        assertNull(s.read())
    }

    @Test
    fun `platform default storage round-trips`() {
        val storage = DesktopSecureStorage.forApp("moon-sso-test", directory = dir)
        storage.storage.write(secret)
        assertEquals(secret, storage.storage.read())
        storage.storage.clear()
        assertNull(storage.storage.read())
    }

    @Test
    fun `key-wrapped file is AES-GCM encrypted and detects tampering`() {
        val keys = MemoryKeys()
        val file = dir.resolve("session.enc")
        val s = KeyWrappedFileStorage(file, keys, "app")
        s.write(secret)
        assertEquals(secret, KeyWrappedFileStorage(file, keys, "app").read())
        val bytes = Files.readAllBytes(file)
        assertFalse(String(bytes, Charsets.ISO_8859_1).contains("rt-secret-value"))
        bytes[bytes.size - 1] = (bytes[bytes.size - 1].toInt() xor 1).toByte()
        Files.write(file, bytes)
        assertFailsWith<Exception> { s.read() }
        // Different app name (AAD) cannot read it either.
        s.write(secret)
        assertFailsWith<Exception> { KeyWrappedFileStorage(file, keys, "other").read() }
    }

    @Test
    fun `plain fallback file is owner-only on POSIX and replaced atomically`() {
        val file = dir.resolve("sub").resolve("session.json")
        val s = PlainFileStorage(file)
        s.write("one")
        s.write(secret)
        assertEquals(secret, s.read())
        assertEquals(listOf("session.json"), Files.list(file.parent).use { st -> st.map { it.fileName.toString() }.toList() })
        if (Platform.isPosix) {
            assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(file)))
        }
    }

    @Test
    fun `app names are validated`() {
        assertFailsWith<IllegalArgumentException> { DesktopSecureStorage.forApp("../evil", directory = dir) }
    }
}
