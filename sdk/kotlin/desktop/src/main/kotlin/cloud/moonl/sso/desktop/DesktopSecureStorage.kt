package cloud.moonl.sso.desktop

import cloud.moonl.sso.MoonSsoLogger
import cloud.moonl.sso.storage.SecureStorage
import com.sun.jna.platform.win32.Crypt32Util
import com.sun.jna.platform.win32.WinCrypt
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.FileSystems
import java.nio.file.Files
import java.nio.file.NoSuchFileException
import java.nio.file.Path
import java.nio.file.Paths
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermissions
import java.security.SecureRandom
import java.util.Base64
import java.util.concurrent.TimeUnit
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

internal object Platform {
    private val os = System.getProperty("os.name").orEmpty().lowercase()
    val isWindows = os.startsWith("windows")
    val isMac = os.startsWith("mac") || os.contains("darwin")
    val isPosix: Boolean = FileSystems.getDefault().supportedFileAttributeViews().contains("posix")
}

/** Kind of secure storage selected for this machine. */
public enum class DesktopStorageKind {
    /** Windows DPAPI (CurrentUser) encrypted file. */
    WINDOWS_DPAPI,

    /** macOS: AES-GCM file whose key lives in the login Keychain. */
    MACOS_KEYCHAIN,

    /** Linux: AES-GCM file whose key lives in the Secret Service (libsecret via `secret-tool`). */
    LINUX_SECRET_SERVICE,

    /** Fallback: plain JSON file readable only by the user (0600). */
    PLAIN_FILE,
}

/** A secure storage plus where its files live (the lock file sits next to it). */
public class DesktopStorage internal constructor(
    public val storage: SecureStorage,
    public val directory: Path,
    public val kind: DesktopStorageKind,
) {
    /** Lock file shared by all processes of this app. */
    public val lockFile: Path get() = directory.resolve("session.lock")
}

/** Picks the best secure storage of the operating system for an application. */
public object DesktopSecureStorage {
    private const val SERVICE = "cloud.moonl.sso"

    /**
     * Storage for [appName] (letters, digits, `.`, `_`, `-`). Files go to
     * `%LOCALAPPDATA%\MoonSSO\<app>` (Windows), `~/Library/Application Support/MoonSSO/<app>` (macOS)
     * or `$XDG_DATA_HOME/moon-sso/<app>` (Linux).
     */
    public fun forApp(appName: String, logger: MoonSsoLogger = MoonSsoLogger.Default, directory: Path? = null): DesktopStorage {
        require(appName.matches(Regex("[A-Za-z0-9._-]{1,64}"))) { "appName may only contain letters, digits, '.', '_' and '-'" }
        val dir = directory ?: defaultDirectory(appName)
        return when {
            Platform.isWindows -> DesktopStorage(DpapiFileStorage(dir.resolve("session.dat"), appName), dir, DesktopStorageKind.WINDOWS_DPAPI)
            Platform.isMac -> DesktopStorage(
                KeyWrappedFileStorage(dir.resolve("session.enc"), MacKeychainKeyStore(SERVICE, appName), appName),
                dir,
                DesktopStorageKind.MACOS_KEYCHAIN,
            )
            SecretToolKeyStore.isAvailable(SERVICE, appName) -> DesktopStorage(
                KeyWrappedFileStorage(dir.resolve("session.enc"), SecretToolKeyStore(SERVICE, appName), appName),
                dir,
                DesktopStorageKind.LINUX_SECRET_SERVICE,
            )
            else -> {
                logger.log(
                    MoonSsoLogger.Level.WARN,
                    "Secret Service (secret-tool) is not available; Moon SSO tokens are stored in a file readable only by this user: " +
                        dir.resolve("session.json"),
                    null,
                )
                DesktopStorage(PlainFileStorage(dir.resolve("session.json")), dir, DesktopStorageKind.PLAIN_FILE)
            }
        }
    }

    internal fun defaultDirectory(appName: String): Path {
        val home = Paths.get(System.getProperty("user.home"))
        return when {
            Platform.isWindows -> {
                val local = System.getenv("LOCALAPPDATA")?.takeIf { it.isNotBlank() }?.let { Paths.get(it) }
                    ?: home.resolve("AppData").resolve("Local")
                local.resolve("MoonSSO").resolve(appName)
            }
            Platform.isMac -> home.resolve("Library").resolve("Application Support").resolve("MoonSSO").resolve(appName)
            else -> {
                val xdg = System.getenv("XDG_DATA_HOME")?.takeIf { it.isNotBlank() }?.let { Paths.get(it) }
                    ?: home.resolve(".local").resolve("share")
                xdg.resolve("moon-sso").resolve(appName)
            }
        }
    }
}

/** Atomic, durable, owner-only file writes. */
internal object SecureFiles {
    fun ensurePrivateDirectory(dir: Path) {
        if (Files.isDirectory(dir)) return
        if (Platform.isPosix) {
            Files.createDirectories(dir, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        } else {
            Files.createDirectories(dir)
        }
    }

    fun readOrNull(file: Path): ByteArray? = try {
        Files.readAllBytes(file)
    } catch (_: NoSuchFileException) {
        null
    }

    /** Writes to a temporary file (0600), forces it to disk, then atomically replaces [file]. */
    fun writeAtomically(file: Path, data: ByteArray) {
        val dir = file.toAbsolutePath().parent
        ensurePrivateDirectory(dir)
        val tmp = if (Platform.isPosix) {
            Files.createTempFile(dir, ".session", ".tmp", PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
        } else {
            Files.createTempFile(dir, ".session", ".tmp")
        }
        try {
            FileChannel.open(tmp, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING).use { ch ->
                val buf = ByteBuffer.wrap(data)
                while (buf.hasRemaining()) ch.write(buf)
                ch.force(true)
            }
            try {
                Files.move(tmp, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            } catch (_: AtomicMoveNotSupportedException) {
                Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING)
            }
        } finally {
            Files.deleteIfExists(tmp)
        }
    }
}

/** Windows: file encrypted with DPAPI for the current user (`CryptProtectData`). */
internal class DpapiFileStorage(private val file: Path, appName: String) : SecureStorage {
    private val entropy = "moon-sso:$appName".toByteArray(Charsets.UTF_8)

    override fun read(): String? {
        val encrypted = SecureFiles.readOrNull(file) ?: return null
        val plain = Crypt32Util.cryptUnprotectData(encrypted, entropy, WinCrypt.CRYPTPROTECT_UI_FORBIDDEN, null)
        try {
            return String(plain, Charsets.UTF_8)
        } finally {
            plain.fill(0)
        }
    }

    override fun write(value: String) {
        val plain = value.toByteArray(Charsets.UTF_8)
        try {
            val encrypted = Crypt32Util.cryptProtectData(plain, entropy, WinCrypt.CRYPTPROTECT_UI_FORBIDDEN, "Moon SSO session", null)
            SecureFiles.writeAtomically(file, encrypted)
        } finally {
            plain.fill(0)
        }
    }

    override fun clear() {
        Files.deleteIfExists(file)
    }
}

/** Fallback: owner-only (0600) JSON file. */
internal class PlainFileStorage(private val file: Path) : SecureStorage {
    override fun read(): String? = SecureFiles.readOrNull(file)?.toString(Charsets.UTF_8)

    override fun write(value: String) = SecureFiles.writeAtomically(file, value.toByteArray(Charsets.UTF_8))

    override fun clear() {
        Files.deleteIfExists(file)
    }
}

/** Stores a small secret (a 256-bit AES key) in an OS keyring. */
internal interface SecretKeyStore {
    /** Returns the stored key, or null when none exists. Throws [IOException] when the keyring fails. */
    fun load(): ByteArray?

    fun save(key: ByteArray)

    fun delete()
}

/**
 * AES-256-GCM encrypted file whose key is kept in an OS keyring ([SecretKeyStore]). Layout:
 * `version(1) | iv(12) | ciphertext+tag`, AAD = app name.
 */
internal class KeyWrappedFileStorage(
    private val file: Path,
    private val keys: SecretKeyStore,
    appName: String,
) : SecureStorage {
    private val aad = "moon-sso:$appName".toByteArray(Charsets.UTF_8)
    private val random = SecureRandom()

    override fun read(): String? {
        val data = SecureFiles.readOrNull(file) ?: return null
        val key = keys.load() ?: throw IOException("the keyring has no key for the stored Moon SSO session")
        require(data.size > 1 + 12 + 16 && data[0] == VERSION) { "unsupported session file format" }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, data, 1, 12))
        cipher.updateAAD(aad)
        val plain = cipher.doFinal(data, 13, data.size - 13)
        try {
            return String(plain, Charsets.UTF_8)
        } finally {
            plain.fill(0)
            key.fill(0)
        }
    }

    override fun write(value: String) {
        val key = keys.load() ?: ByteArray(32).also {
            random.nextBytes(it)
            keys.save(it)
        }
        val iv = ByteArray(12).also(random::nextBytes)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
        cipher.updateAAD(aad)
        val ct = cipher.doFinal(value.toByteArray(Charsets.UTF_8))
        key.fill(0)
        SecureFiles.writeAtomically(file, byteArrayOf(VERSION) + iv + ct)
    }

    override fun clear() {
        Files.deleteIfExists(file)
    }

    private companion object {
        const val VERSION: Byte = 1
    }
}

/** Runs a short-lived command; the secret is passed on stdin, never on the command line. */
internal object Commands {
    class Result(val exit: Int, val stdout: String, val stderr: String)

    fun run(command: List<String>, stdin: String? = null, timeoutSeconds: Long = 60): Result {
        val process = ProcessBuilder(command).start()
        process.outputStream.use { out -> stdin?.let { out.write(it.toByteArray(Charsets.UTF_8)) } }
        val stdout = StringBuilder()
        val stderr = StringBuilder()
        val tOut = Thread { stdout.append(process.inputStream.bufferedReader().readText()) }.apply { isDaemon = true; start() }
        val tErr = Thread { stderr.append(process.errorStream.bufferedReader().readText()) }.apply { isDaemon = true; start() }
        if (!process.waitFor(timeoutSeconds, TimeUnit.SECONDS)) {
            process.destroyForcibly()
            throw IOException("${command.first()} timed out")
        }
        tOut.join(2_000)
        tErr.join(2_000)
        return Result(process.exitValue(), stdout.toString(), stderr.toString())
    }
}

/** macOS login Keychain via the `security` tool (secret sent through `security -i` on stdin). */
internal class MacKeychainKeyStore(private val service: String, private val account: String) : SecretKeyStore {
    override fun load(): ByteArray? {
        val r = Commands.run(listOf("/usr/bin/security", "find-generic-password", "-s", service, "-a", account, "-w"))
        return when (r.exit) {
            0 -> Base64.getDecoder().decode(r.stdout.trim())
            44 -> null // errSecItemNotFound
            else -> throw IOException("security find-generic-password failed (exit ${r.exit})")
        }
    }

    override fun save(key: ByteArray) {
        val b64 = Base64.getEncoder().encodeToString(key)
        val r = Commands.run(
            listOf("/usr/bin/security", "-i"),
            stdin = "add-generic-password -U -s \"$service\" -a \"$account\" -l \"Moon SSO ($account)\" -w \"$b64\"\n",
        )
        if (r.exit != 0 || r.stderr.isNotBlank()) throw IOException("security add-generic-password failed (exit ${r.exit})")
    }

    override fun delete() {
        Commands.run(listOf("/usr/bin/security", "delete-generic-password", "-s", service, "-a", account))
    }
}

/** Linux Secret Service via `secret-tool` (libsecret); the secret is written to its stdin. */
internal class SecretToolKeyStore(private val service: String, private val account: String) : SecretKeyStore {
    override fun load(): ByteArray? {
        val r = Commands.run(listOf("secret-tool", "lookup", "service", service, "account", account))
        return when {
            r.exit == 0 && r.stdout.isNotBlank() -> Base64.getDecoder().decode(r.stdout.trim())
            r.stderr.isBlank() -> null
            else -> throw IOException("secret-tool lookup failed (exit ${r.exit})")
        }
    }

    override fun save(key: ByteArray) {
        val r = Commands.run(
            listOf("secret-tool", "store", "--label=Moon SSO ($account)", "service", service, "account", account),
            stdin = Base64.getEncoder().encodeToString(key),
        )
        if (r.exit != 0) throw IOException("secret-tool store failed (exit ${r.exit})")
    }

    override fun delete() {
        Commands.run(listOf("secret-tool", "clear", "service", service, "account", account))
    }

    companion object {
        /** True when `secret-tool` exists and a Secret Service answers on the session bus. */
        fun isAvailable(service: String, account: String): Boolean = try {
            val r = Commands.run(listOf("secret-tool", "lookup", "service", service, "account", account), timeoutSeconds = 15)
            r.exit == 0 || r.stderr.isBlank()
        } catch (_: Exception) {
            false
        }
    }
}
