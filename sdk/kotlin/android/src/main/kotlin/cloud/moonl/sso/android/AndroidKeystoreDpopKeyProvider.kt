package cloud.moonl.sso.android

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import cloud.moonl.sso.dpop.DpopKey
import cloud.moonl.sso.dpop.DpopKeyProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/**
 * DPoP key in the Android Keystore: a non-exportable P-256 signing key, one per installation
 * (alias per client storage name). Proofs are signed by the Keystore through `java.security.Signature`.
 */
public class AndroidKeystoreDpopKeyProvider(private val alias: String) : DpopKeyProvider {
    @Volatile
    private var cached: DpopKey? = null

    override suspend fun key(): DpopKey = cached ?: withContext(Dispatchers.IO) { loadOrCreate() }

    @Synchronized
    private fun loadOrCreate(): DpopKey {
        cached?.let { return it }
        val ks = KeyStore.getInstance(AndroidKeystore.PROVIDER).apply { load(null) }
        val existing = ks.getKey(alias, null) as? PrivateKey
        val key = if (existing != null) {
            DpopKey(ks.getCertificate(alias).publicKey as ECPublicKey, existing)
        } else {
            val gen = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, AndroidKeystore.PROVIDER)
            gen.initialize(
                KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .build(),
            )
            val pair = gen.generateKeyPair()
            DpopKey(pair.public as ECPublicKey, pair.private)
        }
        cached = key
        return key
    }
}
