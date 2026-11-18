package io.github.encrypteddatastore

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/**
 * Instrumented tests executed on a real Android Emulator / Device with genuine `AndroidKeyStore`.
 */
@RunWith(AndroidJUnit4::class)
class AndroidKeyStoreInstrumentedTest {

    private fun appContext(): Context = ApplicationProvider.getApplicationContext()

    @Test
    fun hardwareBackedStoreStrictRoundTripRotationTamperAndForceReset() = runTest {
        val ctx = appContext()
        val storageCtx = PlatformStorageContext(ctx)
        val config = SecurityConfig(
            storeName = "instrumented_keystore_vault",
            algorithm = CipherAlgorithm.AES256_GCM,
            recoveryPolicy = KeystoreRecoveryPolicy.STRICT,
            preferStrongBox = true,
        )
        val tokenKey = PreferenceKeys.string("token")

        val prefs = EncryptedDataStoreFactory.createPreferences(storageCtx, config)
        prefs.edit { it[tokenKey] = "real_keystore_secret_123" }

        val diag = prefs.diagnostics()
        assertTrue(
            "Expected hardware-backed Keystore on Android device/emulator, got ${diag.securityLevel}",
            diag.hardwareBacked && (diag.securityLevel == SecurityLevel.HARDWARE_TEE || diag.securityLevel == SecurityLevel.STRONGBOX),
        )
        assertEquals(2L, prefs.rotateKeys())
        prefs.close()

        // Reopen fresh instance against real AndroidKeyStore
        val reopened = EncryptedDataStoreFactory.createPreferences(storageCtx, config)
        assertEquals("real_keystore_secret_123", reopened.get(tokenKey))
        reopened.close()

        // Tamper .edst file on disk -> STRICT must fail with StoreTamperedOrCorruptedException
        val (_, storePath) = resolveEncryptedStoreFile(storageCtx, config)
        val file = File(storePath.toString())
        val original = file.readBytes()
        original[original.lastIndex] = (original.last().toInt() xor 0xFF).toByte()
        file.writeBytes(original)

        val tampered = EncryptedDataStoreFactory.createPreferences(storageCtx, config)
        var failedWithTamper = false
        try {
            tampered.get(tokenKey)
        } catch (_: StoreTamperedOrCorruptedException) {
            failedWithTamper = true
        }
        assertTrue("Expected StoreTamperedOrCorruptedException on tampered file", failedWithTamper)

        // forceResetAndClose wipes and allows clean re-creation
        tampered.forceResetAndClose()

        val recovered = EncryptedDataStoreFactory.createPreferences(storageCtx, config)
        assertNull(recovered.get(tokenKey))
        recovered.edit { it[tokenKey] = "after_reset" }
        assertEquals("after_reset", recovered.get(tokenKey))
        recovered.forceResetAndClose()
    }
}
