package io.github.maigsecuritycrypto

import android.content.Context
import android.os.Build
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.KeyStore

/**
 * Instrumented tests executed on an Android Emulator / Device with genuine `AndroidKeyStore`.
 */
@RunWith(AndroidJUnit4::class)
class AndroidKeyStoreInstrumentedTest {

    private val storeName = "instrumented_keystore_vault"

    private fun appContext(): Context = ApplicationProvider.getApplicationContext()

    private fun isEmulator(): Boolean {
        val fp = Build.FINGERPRINT
        val hw = Build.HARDWARE
        val model = Build.MODEL
        return fp.startsWith("generic") ||
            fp.startsWith("unknown") ||
            model.contains("google_sdk") ||
            model.contains("Emulator") ||
            model.contains("Android SDK built for") ||
            hw.contains("goldfish") ||
            hw.contains("ranchu")
    }

    @Before
    fun cleanStoreBeforeTest() {
        val ctx = appContext()
        val storeDir = File(ctx.noBackupFilesDir, "encrypted_datastore")
        listOf(".edst", ".keyset", ".meta", ".swkek").forEach { ext ->
            File(storeDir, "$storeName$ext").delete()
        }
        runCatching {
            val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val alias = AndroidKeyStoreAead.buildAlias(ctx.packageName, storeName)
            if (ks.containsAlias(alias)) {
                ks.deleteEntry(alias)
            }
        }
    }

    @Test
    fun hardwareBackedStoreStrictRoundTripRotationTamperAndForceReset() = runTest {
        val ctx = appContext()
        val storageCtx = MaigStorageContext(ctx)
        val config = MaigSecurityConfig(
            storeName = storeName,
            algorithm = MaigCipherAlgorithm.AES256_GCM,
            recoveryPolicy = MaigKeystoreRecoveryPolicy.STRICT,
            preferStrongBox = true,
        )
        val tokenKey = MaigPreferenceKeys.string("token")

        val prefs = MaigSecurityCrypto.createPreferences(storageCtx, config)
        prefs.edit { it[tokenKey] = "real_keystore_secret_123" }

        val diag = prefs.diagnostics()
        if (isEmulator()) {
            // Android Emulators may report software-emulated Keystore in KeyInfo despite using AndroidKeyStore.
            assertTrue(
                "Unexpected securityLevel on emulator: ${diag.securityLevel}",
                diag.securityLevel in setOf(
                    MaigSecurityLevel.HARDWARE_TEE,
                    MaigSecurityLevel.STRONGBOX,
                    MaigSecurityLevel.SOFTWARE_FALLBACK,
                ),
            )
        } else {
            assertTrue(
                "Expected hardware-backed Keystore on physical Android device, got ${diag.securityLevel}",
                diag.hardwareBacked && (
                    diag.securityLevel == MaigSecurityLevel.HARDWARE_TEE ||
                        diag.securityLevel == MaigSecurityLevel.STRONGBOX
                    ),
            )
        }
        assertEquals(2L, prefs.rotateKeys())
        prefs.close()

        // Reopen fresh instance against real AndroidKeyStore
        val reopened = MaigSecurityCrypto.createPreferences(storageCtx, config)
        assertEquals("real_keystore_secret_123", reopened.get(tokenKey))
        reopened.close()

        // Tamper .edst file on disk -> STRICT must fail with MaigStoreTamperedOrCorruptedException
        val (_, storePath) = resolveEncryptedStoreFile(storageCtx, config)
        val file = File(storePath.toString())
        val original = file.readBytes()
        original[original.lastIndex] = (original.last().toInt() xor 0xFF).toByte()
        file.writeBytes(original)

        val tampered = MaigSecurityCrypto.createPreferences(storageCtx, config)
        var failedWithTamper = false
        try {
            tampered.get(tokenKey)
        } catch (_: MaigStoreTamperedOrCorruptedException) {
            failedWithTamper = true
        }
        assertTrue("Expected MaigStoreTamperedOrCorruptedException on tampered file", failedWithTamper)

        // forceResetAndClose wipes and allows clean re-creation
        tampered.forceResetAndClose()

        val recovered = MaigSecurityCrypto.createPreferences(storageCtx, config)
        assertNull(recovered.get(tokenKey))
        recovered.edit { it[tokenKey] = "after_reset" }
        assertEquals("after_reset", recovered.get(tokenKey))
        recovered.forceResetAndClose()
    }
}
