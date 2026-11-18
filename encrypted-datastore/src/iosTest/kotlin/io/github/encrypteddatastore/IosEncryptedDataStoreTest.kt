package io.github.encrypteddatastore

import kotlin.test.Test
import kotlin.test.assertFailsWith

class IosEncryptedDataStoreTest {

    @Test
    fun `rejects unsupported XCHACHA20_POLY1305 explicitly on iOS`() {
        assertFailsWith<KeyManagementException> {
            EncryptedDataStoreFactory.createPreferences(
                context = PlatformStorageContext(directoryPath = "/tmp/edst_ios_test"),
                config = SecurityConfig(
                    storeName = "ios_xchacha_rejected",
                    algorithm = CipherAlgorithm.XCHACHA20_POLY1305,
                ),
            )
        }
    }
}
