package io.github.encrypteddatastore

import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.take
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.Serializable
import okio.FileSystem
import okio.Path.Companion.toOkioPath
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.days

@Serializable
data class AuthSession(
    val accessToken: String = "",
    val refreshToken: String = "",
    val userId: String = "",
)

@Serializable
data class CustomProfile(
    val id: Long,
    val displayName: String,
    val roles: List<String>,
)

class EncryptedDataStoreSecurityTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    private fun testContext(passphrase: (() -> CharArray)? = null): PlatformStorageContext =
        PlatformStorageContext(
            storageDirectory = tempFolder.root.toOkioPath(),
            fileSystem = FileSystem.SYSTEM,
            masterPassphraseProvider = passphrase,
        )

    private fun storeFilePath(storeName: String) =
        tempFolder.root.toOkioPath() / "encrypted_datastore" / "$storeName.edst"

    @Test
    fun `encrypts payload on disk with EDST envelope and hides plaintext`() = runTest {
        val secretToken = "super_secret_jwt_token_987654321"
        val store = EncryptedDataStoreFactory.create(
            context = testContext(),
            config = SecurityConfig(
                storeName = "session_aes",
                algorithm = CipherAlgorithm.AES256_GCM,
            ),
            serializer = AuthSession.serializer(),
            defaultValue = { AuthSession() },
        )

        store.updateData {
            AuthSession(accessToken = secretToken, refreshToken = "refresh_xyz", userId = "user_42")
        }
        store.close()

        val rawBytes = FileSystem.SYSTEM.read(storeFilePath("session_aes")) { readByteArray() }
        assertTrue(rawBytes.size > EncryptedEnvelopeCodec.HEADER_SIZE)
        assertEquals('E'.code.toByte(), rawBytes[0])
        assertEquals('D'.code.toByte(), rawBytes[1])
        assertEquals('S'.code.toByte(), rawBytes[2])
        assertEquals('T'.code.toByte(), rawBytes[3])
        assertFalse(rawBytes.decodeToString().contains(secretToken))
        assertFalse(rawBytes.decodeToString().contains("refresh_xyz"))

        // Reopen fresh instance from disk and verify decryption
        val reopened = EncryptedDataStoreFactory.create(
            context = testContext(),
            config = SecurityConfig(
                storeName = "session_aes",
                algorithm = CipherAlgorithm.AES256_GCM,
            ),
            serializer = AuthSession.serializer(),
            defaultValue = { AuthSession() },
        )
        assertEquals(secretToken, reopened.get().accessToken)
        assertEquals("user_42", reopened.get().userId)
        reopened.close()
    }

    @Test
    fun `supports XChaCha20-Poly1305 end to end`() = runTest {
        val store = EncryptedDataStoreFactory.create(
            context = testContext(),
            config = SecurityConfig(
                storeName = "session_xchacha",
                algorithm = CipherAlgorithm.XCHACHA20_POLY1305,
            ),
            serializer = AuthSession.serializer(),
            defaultValue = { AuthSession() },
        )

        store.updateData { AuthSession(accessToken = "xchacha_token", userId = "u1") }
        store.close()

        val reopened = EncryptedDataStoreFactory.create(
            context = testContext(),
            config = SecurityConfig(
                storeName = "session_xchacha",
                algorithm = CipherAlgorithm.XCHACHA20_POLY1305,
            ),
            serializer = AuthSession.serializer(),
            defaultValue = { AuthSession() },
        )
        assertEquals("xchacha_token", reopened.get().accessToken)
        assertEquals(CipherAlgorithm.XCHACHA20_POLY1305, reopened.diagnostics().algorithm)
        reopened.close()
    }

    @Test
    fun `detects ciphertext tampering header modification and truncation`() = runTest {
        val store = EncryptedDataStoreFactory.create(
            context = testContext(),
            config = SecurityConfig(
                storeName = "tamper_test",
                recoveryPolicy = KeystoreRecoveryPolicy.STRICT,
            ),
            serializer = AuthSession.serializer(),
            defaultValue = { AuthSession() },
        )
        store.updateData { AuthSession(accessToken = "top_secret") }
        store.close()

        val path = storeFilePath("tamper_test")
        val original = FileSystem.SYSTEM.read(path) { readByteArray() }

        // 1. Flip a byte in the ciphertext payload
        val flippedPayload = original.copyOf()
        flippedPayload[flippedPayload.lastIndex] = (flippedPayload.last().toInt() xor 0xFF).toByte()
        FileSystem.SYSTEM.write(path) { write(flippedPayload) }

        val reopened1 = EncryptedDataStoreFactory.create(
            context = testContext(),
            config = SecurityConfig(
                storeName = "tamper_test",
                recoveryPolicy = KeystoreRecoveryPolicy.STRICT,
            ),
            serializer = AuthSession.serializer(),
            defaultValue = { AuthSession() },
        )
        assertFailsWith<StoreTamperedOrCorruptedException> {
            reopened1.get()
        }
        reopened1.close()

        // 2. Tamper with algorithm byte in header (downgrade attack)
        val flippedHeader = original.copyOf()
        flippedHeader[5] = CipherAlgorithm.XCHACHA20_POLY1305.id
        FileSystem.SYSTEM.write(path) { write(flippedHeader) }

        val reopened2 = EncryptedDataStoreFactory.create(
            context = testContext(),
            config = SecurityConfig(
                storeName = "tamper_test",
                recoveryPolicy = KeystoreRecoveryPolicy.STRICT,
            ),
            serializer = AuthSession.serializer(),
            defaultValue = { AuthSession() },
        )
        assertFailsWith<StoreTamperedOrCorruptedException> {
            reopened2.get()
        }
        reopened2.close()

        // 3. Truncate file to 0 bytes
        FileSystem.SYSTEM.write(path) { /* empty */ }
        val reopened3 = EncryptedDataStoreFactory.create(
            context = testContext(),
            config = SecurityConfig(
                storeName = "tamper_test",
                recoveryPolicy = KeystoreRecoveryPolicy.STRICT,
            ),
            serializer = AuthSession.serializer(),
            defaultValue = { AuthSession() },
        )
        assertFailsWith<StoreTamperedOrCorruptedException> {
            reopened3.get()
        }
        reopened3.close()
    }

    @Test
    fun `rejects dynamic AAD mismatch when bound tenant or user changes`() = runTest {
        var currentTenant = "tenant_A"
        val store = EncryptedDataStoreFactory.create(
            context = testContext(),
            config = SecurityConfig(
                storeName = "aad_bound",
                associatedDataProvider = { currentTenant.encodeToByteArray() },
                recoveryPolicy = KeystoreRecoveryPolicy.STRICT,
            ),
            serializer = AuthSession.serializer(),
            defaultValue = { AuthSession() },
        )
        store.updateData { AuthSession(accessToken = "tenant_secret") }
        store.close()

        currentTenant = "tenant_B"
        val reopened = EncryptedDataStoreFactory.create(
            context = testContext(),
            config = SecurityConfig(
                storeName = "aad_bound",
                associatedDataProvider = { currentTenant.encodeToByteArray() },
                recoveryPolicy = KeystoreRecoveryPolicy.STRICT,
            ),
            serializer = AuthSession.serializer(),
            defaultValue = { AuthSession() },
        )
        assertFailsWith<StoreTamperedOrCorruptedException> {
            reopened.get()
        }
        reopened.close()
    }

    @Test
    fun `prevents cross-store ciphertext swapping`() = runTest {
        val storeA = EncryptedDataStoreFactory.create(
            context = testContext(),
            config = SecurityConfig(storeName = "store_alpha"),
            serializer = AuthSession.serializer(),
            defaultValue = { AuthSession() },
        )
        val storeB = EncryptedDataStoreFactory.create(
            context = testContext(),
            config = SecurityConfig(storeName = "store_beta"),
            serializer = AuthSession.serializer(),
            defaultValue = { AuthSession() },
        )
        storeA.updateData { AuthSession(accessToken = "alpha_secret") }
        storeB.updateData { AuthSession(accessToken = "beta_secret") }
        storeA.close()
        storeB.close()

        // Swap storeA's encrypted file into storeB
        val bytesA = FileSystem.SYSTEM.read(storeFilePath("store_alpha")) { readByteArray() }
        FileSystem.SYSTEM.write(storeFilePath("store_beta")) { write(bytesA) }

        val reopenedB = EncryptedDataStoreFactory.create(
            context = testContext(),
            config = SecurityConfig(
                storeName = "store_beta",
                recoveryPolicy = KeystoreRecoveryPolicy.STRICT,
            ),
            serializer = AuthSession.serializer(),
            defaultValue = { AuthSession() },
        )
        assertFailsWith<StoreTamperedOrCorruptedException> {
            reopenedB.get()
        }
        reopenedB.close()
    }

    @Test
    fun `manual and automatic key rotation re-encrypts and tracks epochs`() = runTest {
        val events = mutableListOf<SecurityEvent>()
        val store = EncryptedDataStoreFactory.create(
            context = testContext(),
            config = SecurityConfig(
                storeName = "rotation_test",
                keyRotationPolicy = KeyRotationPolicy.Automatic(
                    maxKeyAge = 30.days,
                    maxWritesBeforeRotation = 3,
                    maxRetainedKeys = 2,
                ),
                eventListener = { events += it },
            ),
            serializer = AuthSession.serializer(),
            defaultValue = { AuthSession() },
        )

        // 3 writes under epoch 1
        store.updateData { it.copy(accessToken = "t1") }
        store.updateData { it.copy(accessToken = "t2") }
        store.updateData { it.copy(accessToken = "t3") }
        assertEquals(1L, store.diagnostics().currentKeyEpoch)
        assertEquals(3L, store.diagnostics().writesSinceRotation)

        // 4th write triggers automatic rotation before encrypting
        store.updateData { it.copy(accessToken = "t4") }
        assertEquals(2L, store.diagnostics().currentKeyEpoch)
        assertEquals(1L, store.diagnostics().writesSinceRotation)

        // Manual rotation advances to epoch 3
        val epoch3 = store.rotateKeys()
        assertEquals(3L, epoch3)
        assertEquals(3L, store.diagnostics().currentKeyEpoch)
        assertEquals("t4", store.get().accessToken)

        assertTrue(events.any { it is SecurityEvent.KeyRotated && it.trigger == "write_limit" })
        assertTrue(events.any { it is SecurityEvent.KeyRotated && it.trigger == "manual" })
        store.close()
    }

    @Test
    fun `CLEAR_AND_REGENERATE recovers cleanly from corruption and notifies callback`() = runTest {
        val recoveries = mutableListOf<RecoveryEvent>()
        val store = EncryptedDataStoreFactory.create(
            context = testContext(),
            config = SecurityConfig(
                storeName = "recover_test",
                recoveryPolicy = KeystoreRecoveryPolicy.CLEAR_AND_REGENERATE,
                onRecovery = { recoveries += it },
            ),
            serializer = AuthSession.serializer(),
            defaultValue = { AuthSession(accessToken = "default_after_reset") },
        )
        store.updateData { AuthSession(accessToken = "persisted_secret") }
        store.close()

        val path = storeFilePath("recover_test")
        FileSystem.SYSTEM.write(path) { write("corrupted_garbage_bytes".encodeToByteArray()) }

        val reopened = EncryptedDataStoreFactory.create(
            context = testContext(),
            config = SecurityConfig(
                storeName = "recover_test",
                recoveryPolicy = KeystoreRecoveryPolicy.CLEAR_AND_REGENERATE,
                onRecovery = { recoveries += it },
            ),
            serializer = AuthSession.serializer(),
            defaultValue = { AuthSession(accessToken = "default_after_reset") },
        )

        val recoveredValue = reopened.get()
        assertEquals("default_after_reset", recoveredValue.accessToken)
        assertEquals(1, recoveries.size)
        assertEquals("recover_test", recoveries.single().storeName)
        reopened.close()
    }

    @Test
    fun `clearAndReset wipes persisted state and destroys old keys`() = runTest {
        val store = EncryptedDataStoreFactory.create(
            context = testContext(),
            config = SecurityConfig(storeName = "wipe_test"),
            serializer = AuthSession.serializer(),
            defaultValue = { AuthSession() },
        )
        store.updateData { AuthSession(accessToken = "sensitive_before_logout") }

        val backupOfOldCiphertext = FileSystem.SYSTEM.read(storeFilePath("wipe_test")) { readByteArray() }
        store.clearAndReset()

        assertEquals("", store.get().accessToken)
        store.close()

        // Restore old ciphertext snapshot from before wipe: old key must be destroyed!
        FileSystem.SYSTEM.write(storeFilePath("wipe_test")) { write(backupOfOldCiphertext) }
        val reopened = EncryptedDataStoreFactory.create(
            context = testContext(),
            config = SecurityConfig(
                storeName = "wipe_test",
                recoveryPolicy = KeystoreRecoveryPolicy.STRICT,
            ),
            serializer = AuthSession.serializer(),
            defaultValue = { AuthSession() },
        )
        assertFailsWith<StoreTamperedOrCorruptedException> {
            reopened.get()
        }
        reopened.close()
    }

    @Test
    fun `passphrase derived KEK rejects wrong passphrase`() = runTest {
        val store = EncryptedDataStoreFactory.create(
            context = testContext { "correct-horse-battery-staple".toCharArray() },
            config = SecurityConfig(storeName = "pbkdf2_test"),
            serializer = AuthSession.serializer(),
            defaultValue = { AuthSession() },
        )
        store.updateData { AuthSession(accessToken = "locked_secret") }
        assertEquals(SecurityLevel.JVM_KEYSTORE, store.diagnostics().securityLevel)
        store.close()

        val wrongPassStore = EncryptedDataStoreFactory.create(
            context = testContext { "wrong-passphrase".toCharArray() },
            config = SecurityConfig(storeName = "pbkdf2_test"),
            serializer = AuthSession.serializer(),
            defaultValue = { AuthSession() },
        )
        assertFailsWith<KeyManagementException> {
            wrongPassStore.get()
        }
        wrongPassStore.close()
    }

    @Test
    fun `EncryptedPreferences handles all types reactive observation and persistence`() = runTest {
        val prefs = EncryptedDataStoreFactory.createPreferences(
            context = testContext(),
            config = SecurityConfig(storeName = "prefs_test"),
        )

        val kStr = PreferenceKeys.string("token")
        val kInt = PreferenceKeys.int("count")
        val kLong = PreferenceKeys.long("timestamp")
        val kFloat = PreferenceKeys.float("ratio")
        val kDouble = PreferenceKeys.double("precision")
        val kBool = PreferenceKeys.boolean("biometric_enabled")
        val kSet = PreferenceKeys.stringSet("scopes")
        val kBytes = PreferenceKeys.byteArray("hmac_seed")
        val kProfile = PreferenceKeys.serializable("profile", CustomProfile.serializer())

        val observedValues = mutableListOf<String?>()
        val collectJob = launch {
            prefs.observe(kStr).take(3).toList(observedValues)
        }

        prefs.edit {
            it[kStr] = "abc"
            it[kInt] = 42
            it[kLong] = 9_999_999_999L
            it[kFloat] = 3.5f
            it[kDouble] = 3.14159265
            it[kBool] = true
            it[kSet] = setOf("read", "write")
            it[kBytes] = byteArrayOf(1, 2, 3, 4)
            it[kProfile] = CustomProfile(id = 7L, displayName = "Ada", roles = listOf("admin"))
        }
        prefs.edit {
            // Change another key: observe(kStr) must NOT emit duplicate "abc"
            it[kInt] = 43
        }
        prefs.edit {
            it[kStr] = "def"
        }
        collectJob.join()
        prefs.close()

        assertEquals(listOf(null, "abc", "def"), observedValues)

        val reopened = EncryptedDataStoreFactory.createPreferences(
            context = testContext(),
            config = SecurityConfig(storeName = "prefs_test"),
        )
        val snap = reopened.data.first()
        assertEquals("def", snap[kStr])
        assertEquals(43, snap[kInt])
        assertEquals(9_999_999_999L, snap[kLong])
        assertEquals(3.5f, snap[kFloat])
        assertEquals(3.14159265, snap[kDouble])
        assertEquals(true, snap[kBool])
        assertEquals(setOf("read", "write"), snap[kSet])
        assertContentEquals(byteArrayOf(1, 2, 3, 4), snap[kBytes])
        assertEquals(CustomProfile(7L, "Ada", listOf("admin")), snap[kProfile])

        reopened.edit { it.remove(kStr) }
        assertNull(reopened.get(kStr))
        assertFalse(reopened.contains(kStr))
        assertNotEquals(0, reopened.data.first().keys().size)
        reopened.close()
    }
}
