package io.github.encrypteddatastore.sample

import android.app.Application
import io.github.encrypteddatastore.CipherAlgorithm
import io.github.encrypteddatastore.EncryptedDataStoreFactory
import io.github.encrypteddatastore.EncryptedPreferences
import io.github.encrypteddatastore.KeystoreRecoveryPolicy
import io.github.encrypteddatastore.PlatformStorageContext
import io.github.encrypteddatastore.SecurityConfig

class SampleApplication : Application() {
    val vaultPrefs: EncryptedPreferences by lazy {
        EncryptedDataStoreFactory.createPreferences(
            context = PlatformStorageContext(applicationContext),
            config = SecurityConfig(
                storeName = "sample_vault",
                algorithm = CipherAlgorithm.AES256_GCM,
                recoveryPolicy = KeystoreRecoveryPolicy.STRICT,
            ),
        )
    }
}
