package cloud.moonl.sso.android

import android.annotation.SuppressLint
import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import cloud.moonl.sso.MoonSsoLogger
import cloud.moonl.sso.storage.SecureStorage
import okio.ByteString.Companion.decodeBase64
import okio.ByteString.Companion.toByteString
import java.security.GeneralSecurityException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Minimal key-value persistence (SharedPreferences in production, a map in unit tests). */
internal interface KeyValueStore {
    fun get(key: String): String?

    /** Synchronously and durably stores [value] (SharedPreferences.commit). */
    fun put(key: String, value: String)

    fun remove(key: String)
}

/** Uses `commit()` on purpose: a rotated refresh token must be on disk before it is used. */
@SuppressLint("ApplySharedPref")
internal class SharedPreferencesStore(private val prefs: SharedPreferences) : KeyValueStore {
    override fun get(key: String): String? = prefs.getString(key, null)

    override fun put(key: String, value: String) {
        if (!prefs.edit().putString(key, value).commit()) throw java.io.IOException("SharedPreferences commit failed")
    }

    override fun remove(key: String) {
        prefs.edit().remove(key).commit()
    }
}

/** AES-256-GCM with a 128-bit tag; output layout `version(1) | iv(12) | ciphertext+tag`. */
internal class AesGcmEncryptor(private val key: () -> SecretKey) {
    fun encrypt(plain: ByteArray, aad: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        // The Keystore requires randomized encryption: the provider chooses the IV.
        cipher.init(Cipher.ENCRYPT_MODE, key())
        cipher.updateAAD(aad)
        val ct = cipher.doFinal(plain)
        val iv = cipher.iv
        check(iv.size == IV_SIZE) { "unexpected GCM IV size" }
        return byteArrayOf(VERSION) + iv + ct
    }

    fun decrypt(data: ByteArray, aad: ByteArray): ByteArray {
        if (data.size < 1 + IV_SIZE + 16 || data[0] != VERSION) throw GeneralSecurityException("unsupported ciphertext format")
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, data, 1, IV_SIZE))
        cipher.updateAAD(aad)
        return cipher.doFinal(data, 1 + IV_SIZE, data.size - 1 - IV_SIZE)
    }

    private companion object {
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val IV_SIZE = 12
        const val VERSION: Byte = 1
    }
}

/** One encrypted string under [entryKey] of a [KeyValueStore]. Undecryptable data reads as empty and is removed. */
internal class EncryptedValueStorage(
    private val kv: KeyValueStore,
    private val entryKey: String,
    private val encryptor: AesGcmEncryptor,
    private val logger: MoonSsoLogger,
) : SecureStorage {
    private val aad = "moon-sso:$entryKey".toByteArray(Charsets.UTF_8)

    override fun read(): String? {
        val stored = kv.get(entryKey) ?: return null
        return try {
            val bytes = stored.decodeBase64()?.toByteArray() ?: throw GeneralSecurityException("not base64")
            val plain = encryptor.decrypt(bytes, aad)
            try {
                String(plain, Charsets.UTF_8)
            } finally {
                plain.fill(0)
            }
        } catch (e: GeneralSecurityException) {
            // Key invalidated (e.g. device restored from backup) or data corrupted: start signed out.
            logger.log(MoonSsoLogger.Level.WARN, "stored Moon SSO data could not be decrypted; discarding it", e)
            kv.remove(entryKey)
            null
        }
    }

    override fun write(value: String) {
        val plain = value.toByteArray(Charsets.UTF_8)
        try {
            kv.put(entryKey, encryptor.encrypt(plain, aad).toByteString().base64())
        } finally {
            plain.fill(0)
        }
    }

    override fun clear() = kv.remove(entryKey)
}

/** Keys held by the Android Keystore (never exportable). */
internal object AndroidKeystore {
    const val PROVIDER = "AndroidKeyStore"

    private fun keyStore(): KeyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }

    @Synchronized
    fun aesKey(alias: String): SecretKey {
        (keyStore().getKey(alias, null) as? SecretKey)?.let { return it }
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER)
        gen.init(
            KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true)
                .build(),
        )
        return gen.generateKey()
    }
}

/**
 * Session storage for Android: the JSON is encrypted with an AES-256-GCM key from the Android
 * Keystore and kept in private SharedPreferences (written with `commit()` so rotated refresh tokens
 * are durable). Exclude the preferences file from backups (`android:allowBackup` / data extraction
 * rules): a restored copy cannot be decrypted on another device anyway and is discarded.
 */
public object KeystoreSecureStorage {
    /** Preferences file name used for [name]. */
    public fun preferencesName(name: String): String = "cloud.moonl.sso.$name"

    /** Creates the storage for [name] (one per client/session). */
    public fun create(context: Context, name: String = "default", logger: MoonSsoLogger = MoonSsoLogger.Default): SecureStorage {
        require(name.matches(Regex("[A-Za-z0-9._-]{1,64}"))) { "name may only contain letters, digits, '.', '_' and '-'" }
        val prefs = context.applicationContext.getSharedPreferences(preferencesName(name), Context.MODE_PRIVATE)
        val alias = "cloud.moonl.sso.$name.aes"
        return EncryptedValueStorage(SharedPreferencesStore(prefs), "session", AesGcmEncryptor { AndroidKeystore.aesKey(alias) }, logger)
    }

    internal fun pendingAuthStorage(context: Context, name: String, logger: MoonSsoLogger): SecureStorage {
        val prefs = context.applicationContext.getSharedPreferences(preferencesName(name), Context.MODE_PRIVATE)
        val alias = "cloud.moonl.sso.$name.aes"
        return EncryptedValueStorage(SharedPreferencesStore(prefs), "pending_authorization", AesGcmEncryptor { AndroidKeystore.aesKey(alias) }, logger)
    }
}
