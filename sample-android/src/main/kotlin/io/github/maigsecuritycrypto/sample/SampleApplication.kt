package io.github.maigsecuritycrypto.sample

import android.app.Application
import io.github.maigsecuritycrypto.MaigCipherAlgorithm
import io.github.maigsecuritycrypto.MaigEncryptedPreferences
import io.github.maigsecuritycrypto.MaigKeystoreRecoveryPolicy
import io.github.maigsecuritycrypto.MaigSecurityConfig
import io.github.maigsecuritycrypto.MaigSecurityCrypto
import io.github.maigsecuritycrypto.MaigStorageContext

class SampleApplication : Application() {
    val vaultPrefs: MaigEncryptedPreferences by lazy {
        MaigSecurityCrypto.createPreferences(
            context = MaigStorageContext(applicationContext),
            config = MaigSecurityConfig(
                storeName = "sample_vault",
                algorithm = MaigCipherAlgorithm.AES256_GCM,
                recoveryPolicy = MaigKeystoreRecoveryPolicy.STRICT,
            ),
        )
    }
}
