package io.github.encrypteddatastore

import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import okio.FileSystem
import okio.Path.Companion.toPath
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class IosEncryptedDataStoreTest {

    @Test
    fun `rejects unsupported AES256_GCM and XCHACHA20_POLY1305 explicitly on iOS`() {
        assertFailsWith<KeyManagementException> {
            EncryptedDataStoreFactory.createPreferences(
                context = PlatformStorageContext(directoryPath = "/tmp/edst_ios_test"),
                config = SecurityConfig(
                    storeName = "ios_xchacha_rejected",
                    algorithm = CipherAlgorithm.XCHACHA20_POLY1305,
                ),
            )
        }
        assertFailsWith<KeyManagementException> {
            EncryptedDataStoreFactory.createPreferences(
                context = PlatformStorageContext(directoryPath = "/tmp/edst_ios_test"),
                config = SecurityConfig(
                    storeName = "ios_gcm_rejected",
                    algorithm = CipherAlgorithm.AES256_GCM,
                ),
            )
        }
    }

    @Test
    fun `IosKeychainKeysetRecord serializes and deserializes cleanly`() {
        val record = IosKeychainKeysetRecord(
            currentEpoch = 3L,
            keyCreatedAtEpochMs = 1_700_000_000L,
            writesSinceRotation = 5L,
            epochKeysBase64 = mapOf(2L to "AAAA", 3L to "BBBB"),
        )
        val encoded = Json.encodeToString(IosKeychainKeysetRecord.serializer(), record)
        val decoded = Json.decodeFromString(IosKeychainKeysetRecord.serializer(), encoded)
        assertEquals(record, decoded)
    }

    @Test
    fun `Keychain lifecycle round-trip or clean missing-entitlement error in simulator`() = runTest {
        val testDir = "/tmp/edst_ios_sim_test"
        FileSystem.SYSTEM.createDirectories(testDir.toPath())
        val prefs = EncryptedDataStoreFactory.createPreferences(
            context = PlatformStorageContext(
                directoryPath = testDir,
                keychainService = "io.github.encrypteddatastore.iostest",
            ),
            config = SecurityConfig(
                storeName = "ios_lifecycle",
                algorithm = CipherAlgorithm.AES256_CTR_HMAC_SHA256,
                userAuthConfig = null,
            ),
        )
        val tokenKey = PreferenceKeys.string("ios_token")
        try {
            prefs.edit { it[tokenKey] = "ios_secret_123" }
            assertEquals("ios_secret_123", prefs.get(tokenKey))
            assertEquals(2L, prefs.rotateKeys())
            assertEquals("ios_secret_123", prefs.get(tokenKey))
            val diag = prefs.diagnostics()
            assertEquals(CipherAlgorithm.AES256_CTR_HMAC_SHA256, diag.algorithm)
            assertEquals(SecurityLevel.KEYCHAIN, diag.securityLevel)
            assertFalse(diag.hardwareBacked)
            prefs.clearAndReset()
            assertNull(prefs.get(tokenKey))
            prefs.forceResetAndClose()
        } catch (e: KeystoreUnavailableException) {
            // Unsigned Kotlin/Native XCTest runner binaries may lack Keychain entitlements (-34018)
            assertTrue(e.message?.contains("OSStatus=") == true)
            prefs.close()
        }
    }
}
