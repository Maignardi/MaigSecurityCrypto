package io.github.maigsecuritycrypto

import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import okio.FileSystem
import okio.Path.Companion.toPath
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class IosEncryptedDataStoreTest {

    @Test
    fun `rejects unsupported AES256_GCM and XCHACHA20_POLY1305 explicitly on iOS`() {
        assertFailsWith<MaigKeyManagementException> {
            MaigSecurityCrypto.createPreferences(
                context = MaigStorageContext(directoryPath = "/tmp/edst_ios_test"),
                config = MaigSecurityConfig(
                    storeName = "ios_xchacha_rejected",
                    algorithm = MaigCipherAlgorithm.XCHACHA20_POLY1305,
                ),
            )
        }
        assertFailsWith<MaigKeyManagementException> {
            MaigSecurityCrypto.createPreferences(
                context = MaigStorageContext(directoryPath = "/tmp/edst_ios_test"),
                config = MaigSecurityConfig(
                    storeName = "ios_gcm_rejected",
                    algorithm = MaigCipherAlgorithm.AES256_GCM,
                ),
            )
        }
    }

    @Test
    fun `IosAesCtrHmacCipher round-trip and detects tampering AAD mismatch and truncation`() = runTest {
        val masterKey = ByteArray(32) { (it + 1).toByte() }
        val iv = ByteArray(16) { (it + 10).toByte() }
        val aad = "EDST_IOS_TEST_AAD".encodeToByteArray()
        val plaintext = "sensitive_ios_payload_42".encodeToByteArray()

        val payload = IosAesCtrHmacCipher.encrypt(masterKey, plaintext, aad, iv)
        assertEquals(IosAesCtrHmacCipher.IV_BYTES + plaintext.size + IosAesCtrHmacCipher.MAC_TAG_BYTES, payload.size)

        val decrypted = IosAesCtrHmacCipher.decrypt(masterKey, payload, aad, "kat_store", 1L)
        assertContentEquals(plaintext, decrypted)

        // Tamper ciphertext byte
        val tamperedCt = payload.copyOf().apply { this[IosAesCtrHmacCipher.IV_BYTES] = (this[IosAesCtrHmacCipher.IV_BYTES].toInt() xor 0xFF).toByte() }
        assertFailsWith<MaigStoreTamperedOrCorruptedException> {
            IosAesCtrHmacCipher.decrypt(masterKey, tamperedCt, aad, "kat_store", 1L)
        }

        // Tamper HMAC tag byte
        val tamperedTag = payload.copyOf().apply { this[lastIndex] = (last().toInt() xor 0x01).toByte() }
        assertFailsWith<MaigStoreTamperedOrCorruptedException> {
            IosAesCtrHmacCipher.decrypt(masterKey, tamperedTag, aad, "kat_store", 1L)
        }

        // Wrong AAD
        assertFailsWith<MaigStoreTamperedOrCorruptedException> {
            IosAesCtrHmacCipher.decrypt(masterKey, payload, "WRONG_AAD".encodeToByteArray(), "kat_store", 1L)
        }

        // Truncated payload
        assertFailsWith<MaigStoreTamperedOrCorruptedException> {
            IosAesCtrHmacCipher.decrypt(masterKey, ByteArray(10), aad, "kat_store", 1L)
        }
    }

    @Test
    fun `IosAesCtrHmacCipher matches independent Python and OpenSSL known-answer test vector`() = runTest {
        val masterKey = ByteArray(32) { it.toByte() }
        val iv = ByteArray(16) { (0x10 + it).toByte() }
        val aad = "EDST_IOS_KAT_AAD".encodeToByteArray()
        val plaintext = "Hello, EncryptedDataStore KAT!".encodeToByteArray()

        // Generated independently via Python hmac/hashlib + `openssl enc -aes-256-ctr`
        val expectedHex =
            "101112131415161718191a1b1c1d1e1f" +
                "a2bd229e691afb144846ef49f134bf3cd7e69d62415bfa35cedee5fb3e2c" +
                "a9a6e7bd5768b6da8db86ee9d2b00a2d57eb0019dd1b19abef96a4a52c0440a3"
        val expectedPayload = expectedHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

        val actualPayload = IosAesCtrHmacCipher.encrypt(masterKey, plaintext, aad, iv)
        assertContentEquals(expectedPayload, actualPayload)

        val actualPlaintext = IosAesCtrHmacCipher.decrypt(masterKey, expectedPayload, aad, "kat", 1L)
        assertContentEquals(plaintext, actualPlaintext)
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
        val prefs = MaigSecurityCrypto.createPreferences(
            context = MaigStorageContext(
                directoryPath = testDir,
                keychainService = "io.github.maigsecuritycrypto.iostest",
            ),
            config = MaigSecurityConfig(
                storeName = "ios_lifecycle",
                algorithm = MaigCipherAlgorithm.AES256_CTR_HMAC_SHA256,
                userAuthConfig = null,
            ),
        )
        val tokenKey = MaigPreferenceKeys.string("ios_token")
        try {
            prefs.edit { it[tokenKey] = "ios_secret_123" }
            assertEquals("ios_secret_123", prefs.get(tokenKey))
            assertEquals(2L, prefs.rotateKeys())
            assertEquals("ios_secret_123", prefs.get(tokenKey))
            val diag = prefs.diagnostics()
            assertEquals(MaigCipherAlgorithm.AES256_CTR_HMAC_SHA256, diag.algorithm)
            assertEquals(MaigSecurityLevel.KEYCHAIN, diag.securityLevel)
            assertFalse(diag.hardwareBacked)
            prefs.clearAndReset()
            assertNull(prefs.get(tokenKey))
            prefs.forceResetAndClose()
        } catch (e: MaigKeystoreUnavailableException) {
            // Unsigned Kotlin/Native XCTest runner binaries may lack Keychain entitlements (-34018)
            assertTrue(e.message?.contains("OSStatus=") == true)
            prefs.close()
        }
    }
}
