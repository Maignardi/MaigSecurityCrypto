package io.github.encrypteddatastore.sample

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.material3.MaterialTheme
import io.github.encrypteddatastore.CipherAlgorithm
import io.github.encrypteddatastore.EncryptedDataStoreFactory
import io.github.encrypteddatastore.KeystoreRecoveryPolicy
import io.github.encrypteddatastore.PlatformStorageContext
import io.github.encrypteddatastore.SecurityConfig

class MainActivity : ComponentActivity() {

    private val vaultPrefs by lazy {
        EncryptedDataStoreFactory.createPreferences(
            context = PlatformStorageContext(applicationContext),
            config = SecurityConfig(
                storeName = "sample_vault",
                algorithm = CipherAlgorithm.AES256_GCM,
                recoveryPolicy = KeystoreRecoveryPolicy.STRICT,
            ),
        )
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                EncryptedVaultScreen(prefs = vaultPrefs)
            }
        }
    }
}
