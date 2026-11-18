package io.github.maigsecuritycrypto

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

    private fun testContext(passphrase: (() -> CharArray)? = null): MaigStorageContext =
        MaigStorageContext(
            storageDirectory = tempFolder.root.toOkioPath(),
            fileSystem = FileSystem.SYSTEM,
            masterPassphraseProvider = passphrase,
        )

    private fun storeFilePath(storeName: String) =
        tempFolder.root.toOkioPath() / "encrypted_datastore" / "$storeName.edst"

    @Test
    fun `encrypts payload on disk with EDST envelope and hides plaintext`() = runTest {
        val secretToken = "super_secret_jwt_token_987654321"
        val store = MaigSecurityCrypto.create(
            context = testContext(),
            config = MaigSecurityConfig(
                storeName = "session_aes",
                algorithm = MaigCipherAlgorithm.AES256_GCM,
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
        val reopened = MaigSecurityCrypto.create(
            context = testContext(),
            config = MaigSecurityConfig(
                storeName = "session_aes",
                algorithm = MaigCipherAlgorithm.AES256_GCM,
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
        val store = MaigSecurityCrypto.create(
            context = testContext(),
            config = MaigSecurityConfig(
                storeName = "session_xchacha",
                algorithm = MaigCipherAlgorithm.XCHACHA20_POLY1305,
            ),
            serializer = AuthSession.serializer(),
            defaultValue = { AuthSession() },
        )

        store.updateData { AuthSession(accessToken = "xchacha_token", userId = "u1") }
        store.close()

        val reopened = MaigSecurityCrypto.create(
            context = testContext(),
            config = MaigSecurityConfig(
                storeName = "session_xchacha",
                algorithm = MaigCipherAlgorithm.XCHACHA20_POLY1305,
            ),
            serializer = AuthSession.serializer(),
            defaultValue = { AuthSession() },
        )
        assertEquals("xchacha_token", reopened.get().accessToken)
        assertEquals(MaigCipherAlgorithm.XCHACHA20_POLY1305, reopened.diagnostics().algorithm)
        reopened.close()
    }

    @Test
    fun `detects ciphertext tampering header modification and truncation`() = runTest {
        val store = MaigSecurityCrypto.create(
            context = testContext(),
            config = MaigSecurityConfig(
                storeName = "tamper_test",
                recoveryPolicy = MaigKeystoreRecoveryPolicy.STRICT,
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

        val reopened1 = MaigSecurityCrypto.create(
            context = testContext(),
            config = MaigSecurityConfig(
                storeName = "tamper_test",
                recoveryPolicy = MaigKeystoreRecoveryPolicy.STRICT,
            ),
            serializer = AuthSession.serializer(),
            defaultValue = { AuthSession() },
        )
        assertFailsWith<MaigStoreTamperedOrCorruptedException> {
            reopened1.get()
        }
        reopened1.close()

        // 2. Tamper with algorithm byte in header (downgrade attack)
        val flippedHeader = original.copyOf()
        flippedHeader[5] = MaigCipherAlgorithm.XCHACHA20_POLY1305.id
        FileSystem.SYSTEM.write(path) { write(flippedHeader) }

        val reopened2 = MaigSecurityCrypto.create(
            context = testContext(),
            config = MaigSecurityConfig(
                storeName = "tamper_test",
                recoveryPolicy = MaigKeystoreRecoveryPolicy.STRICT,
            ),
            serializer = AuthSession.serializer(),
            defaultValue = { AuthSession() },
        )
        assertFailsWith<MaigStoreTamperedOrCorruptedException> {
            reopened2.get()
        }
        reopened2.close()

        // 3. Truncate file to 0 bytes
        FileSystem.SYSTEM.write(path) { /* empty */ }
        val reopened3 = MaigSecurityCrypto.create(
            context = testContext(),
            config = MaigSecurityConfig(
                storeName = "tamper_test",
                recoveryPolicy = MaigKeystoreRecoveryPolicy.STRICT,
            ),
            serializer = AuthSession.serializer(),
            defaultValue = { AuthSession() },
        )
        assertFailsWith<MaigStoreTamperedOrCorruptedException> {
            reopened3.get()
        }
        reopened3.close()
    }

    @Test
    fun `rejects dynamic AAD mismatch when bound tenant or user changes`() = runTest {
        var currentTenant = "tenant_A"
        val store = MaigSecurityCrypto.create(
            context = testContext(),
            config = MaigSecurityConfig(
                storeName = "aad_bound",
                associatedDataProvider = { currentTenant.encodeToByteArray() },
                recoveryPolicy = MaigKeystoreRecoveryPolicy.STRICT,
            ),
            serializer = AuthSession.serializer(),
            defaultValue = { AuthSession() },
        )
        store.updateData { AuthSession(accessToken = "tenant_secret") }
        store.close()

        currentTenant = "tenant_B"
        val reopened = MaigSecurityCrypto.create(
            context = testContext(),
            config = MaigSecurityConfig(
                storeName = "aad_bound",
                associatedDataProvider = { currentTenant.encodeToByteArray() },
                recoveryPolicy = MaigKeystoreRecoveryPolicy.STRICT,
            ),
            serializer = AuthSession.serializer(),
            defaultValue = { AuthSession() },
        )
        assertFailsWith<MaigStoreTamperedOrCorruptedException> {
            reopened.get()
        }
        reopened.close()
    }

    @Test
    fun `prevents cross-store ciphertext swapping`() = runTest {
        val storeA = MaigSecurityCrypto.create(
            context = testContext(),
            config = MaigSecurityConfig(storeName = "store_alpha"),
            serializer = AuthSession.serializer(),
            defaultValue = { AuthSession() },
        )
        val storeB = MaigSecurityCrypto.create(
            context = testContext(),
            config = MaigSecurityConfig(storeName = "store_beta"),
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

        val reopenedB = MaigSecurityCrypto.create(
            context = testContext(),
            config = MaigSecurityConfig(
                storeName = "store_beta",
                recoveryPolicy = MaigKeystoreRecoveryPolicy.STRICT,
            ),
            serializer = AuthSession.serializer(),
            defaultValue = { AuthSession() },
        )
        assertFailsWith<MaigStoreTamperedOrCorruptedException> {
            reopenedB.get()
        }
        reopenedB.close()
    }

    @Test
    fun `manual and automatic key rotation re-encrypts and tracks epochs`() = runTest {
        val events = mutableListOf<MaigSecurityEvent>()
        val store = MaigSecurityCrypto.create(
            context = testContext(),
            config = MaigSecurityConfig(
                storeName = "rotation_test",
                keyRotationPolicy = MaigKeyRotationPolicy.Automatic(
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

        assertTrue(events.any { it is MaigSecurityEvent.KeyRotated && it.trigger == "write_limit" })
        assertTrue(events.any { it is MaigSecurityEvent.KeyRotated && it.trigger == "manual" })
        store.close()
    }

    @Test
    fun `CLEAR_AND_REGENERATE recovers cleanly from corruption and notifies callback`() = runTest {
        val recoveries = mutableListOf<MaigRecoveryEvent>()
        val store = MaigSecurityCrypto.create(
            context = testContext(),
            config = MaigSecurityConfig(
                storeName = "recover_test",
                recoveryPolicy = MaigKeystoreRecoveryPolicy.CLEAR_AND_REGENERATE,
                onRecovery = { recoveries += it },
            ),
            serializer = AuthSession.serializer(),
            defaultValue = { AuthSession(accessToken = "default_after_reset") },
        )
        store.updateData { AuthSession(accessToken = "persisted_secret") }
        store.close()

        val path = storeFilePath("recover_test")
        FileSystem.SYSTEM.write(path) { write("corrupted_garbage_bytes".encodeToByteArray()) }

        val reopened = MaigSecurityCrypto.create(
            context = testContext(),
            config = MaigSecurityConfig(
                storeName = "recover_test",
                recoveryPolicy = MaigKeystoreRecoveryPolicy.CLEAR_AND_REGENERATE,
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
        val store = MaigSecurityCrypto.create(
            context = testContext(),
            config = MaigSecurityConfig(storeName = "wipe_test"),
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
        val reopened = MaigSecurityCrypto.create(
            context = testContext(),
            config = MaigSecurityConfig(
                storeName = "wipe_test",
                recoveryPolicy = MaigKeystoreRecoveryPolicy.STRICT,
            ),
            serializer = AuthSession.serializer(),
            defaultValue = { AuthSession() },
        )
        assertFailsWith<MaigStoreTamperedOrCorruptedException> {
            reopened.get()
        }
        reopened.close()
    }

    @Test
    fun `passphrase derived KEK rejects wrong passphrase and preserves caller CharArray`() = runTest {
        val reusablePassphrase = "correct-horse-battery-staple".toCharArray()
        val store = MaigSecurityCrypto.create(
            context = testContext { reusablePassphrase },
            config = MaigSecurityConfig(storeName = "pbkdf2_test"),
            serializer = AuthSession.serializer(),
            defaultValue = { AuthSession() },
        )
        store.updateData { AuthSession(accessToken = "locked_secret") }
        assertEquals(MaigSecurityLevel.PASSPHRASE_PBKDF2, store.diagnostics().securityLevel)
        // Ensure caller's buffer was NOT zeroed and works across rotation and reopen
        assertEquals("correct-horse-battery-staple", reusablePassphrase.concatToString())
        store.rotateKeys()
        assertEquals("correct-horse-battery-staple", reusablePassphrase.concatToString())
        store.close()

        val reopenedOk = MaigSecurityCrypto.create(
            context = testContext { reusablePassphrase },
            config = MaigSecurityConfig(storeName = "pbkdf2_test"),
            serializer = AuthSession.serializer(),
            defaultValue = { AuthSession() },
        )
        assertEquals("locked_secret", reopenedOk.get().accessToken)
        reopenedOk.close()

        val wrongPassStore = MaigSecurityCrypto.create(
            context = testContext { "wrong-passphrase".toCharArray() },
            config = MaigSecurityConfig(storeName = "pbkdf2_test"),
            serializer = AuthSession.serializer(),
            defaultValue = { AuthSession() },
        )
        assertFailsWith<MaigKeyManagementException> {
            wrongPassStore.get()
        }
        wrongPassStore.close()
    }

    @Test
    fun `wrong passphrase does not poison KEK cache or wipe store under CLEAR_AND_REGENERATE`() = runTest {
        val store = MaigSecurityCrypto.create(
            context = testContext { "vault-pass-1".toCharArray() },
            config = MaigSecurityConfig(
                storeName = "pass_no_wipe",
                recoveryPolicy = MaigKeystoreRecoveryPolicy.CLEAR_AND_REGENERATE,
            ),
            serializer = AuthSession.serializer(),
            defaultValue = { AuthSession() },
        )
        store.updateData { AuthSession(accessToken = "precious_data") }
        store.close()

        // Same instance receives wrong passphrase first, then correct passphrase: must NOT poison cache
        var dynamicPass = "wrong-pass"
        val dynamicStore = MaigSecurityCrypto.create(
            context = testContext { dynamicPass.toCharArray() },
            config = MaigSecurityConfig(
                storeName = "pass_no_wipe",
                recoveryPolicy = MaigKeystoreRecoveryPolicy.CLEAR_AND_REGENERATE,
            ),
            serializer = AuthSession.serializer(),
            defaultValue = { AuthSession() },
        )
        assertFailsWith<MaigKeyManagementException> {
            dynamicStore.get()
        }

        // Now provide the right passphrase on the SAME instance: data must still be intact!
        dynamicPass = "vault-pass-1"
        assertEquals("precious_data", dynamicStore.get().accessToken)
        dynamicStore.close()
    }

    @Test
    fun `forceResetAndClose recovers a corrupted STRICT store cleanly`() = runTest {
        val store = MaigSecurityCrypto.create(
            context = testContext(),
            config = MaigSecurityConfig(
                storeName = "force_reset_strict",
                recoveryPolicy = MaigKeystoreRecoveryPolicy.STRICT,
            ),
            serializer = AuthSession.serializer(),
            defaultValue = { AuthSession(accessToken = "fresh") },
        )
        store.updateData { AuthSession(accessToken = "before_corruption") }
        store.close()

        FileSystem.SYSTEM.write(storeFilePath("force_reset_strict")) {
            write("corrupted_bytes".encodeToByteArray())
        }

        val broken = MaigSecurityCrypto.create(
            context = testContext(),
            config = MaigSecurityConfig(
                storeName = "force_reset_strict",
                recoveryPolicy = MaigKeystoreRecoveryPolicy.STRICT,
            ),
            serializer = AuthSession.serializer(),
            defaultValue = { AuthSession(accessToken = "fresh") },
        )
        assertFailsWith<MaigStoreTamperedOrCorruptedException> {
            broken.get()
        }
        broken.forceResetAndClose()

        val recreated = MaigSecurityCrypto.create(
            context = testContext(),
            config = MaigSecurityConfig(
                storeName = "force_reset_strict",
                recoveryPolicy = MaigKeystoreRecoveryPolicy.STRICT,
            ),
            serializer = AuthSession.serializer(),
            defaultValue = { AuthSession(accessToken = "fresh") },
        )
        assertEquals("fresh", recreated.get().accessToken)
        recreated.close()
    }

    @Test
    fun `opens JVM store encrypted with legacy 0_1_2 storeName-duplicated AAD and migrates it`() = runTest {
        val storeName = "legacy_v012_store"
        val storeDir = tempFolder.root.toOkioPath() / "encrypted_datastore"
        FileSystem.SYSTEM.createDirectories(storeDir)

        // Create a valid store first, then re-wrap keyset and metadata with 0.1.2's "storeName:storeName" AAD
        val store = MaigSecurityCrypto.create(
            context = testContext { "pass123".toCharArray() },
            config = MaigSecurityConfig(storeName = storeName),
            serializer = AuthSession.serializer(),
            defaultValue = { AuthSession() },
        )
        store.updateData { AuthSession(accessToken = "legacy_012_secret") }
        store.close()

        // Manually re-encrypt keyset with duplicated AAD ("legacy_v012_store:legacy_v012_store")
        val salt = FileSystem.SYSTEM.read(storeDir / "$storeName.kek") { readByteArray() }
        val factory = javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val derived = factory.generateSecret(
            javax.crypto.spec.PBEKeySpec("pass123".toCharArray(), salt, 310_000, 256)
        ).encoded
        val kekAead = com.google.crypto.tink.subtle.AesGcmJce(derived)
        fun domainAad(tag: String, scope: String): ByteArray = okio.Buffer().apply {
            val t = tag.encodeToByteArray()
            val s = scope.encodeToByteArray()
            writeInt(t.size); write(t); writeInt(s.size); write(s)
        }.readByteArray()

        val keysetBytes = FileSystem.SYSTEM.read(storeDir / "$storeName.keyset") { readByteArray() }
        val handle = com.google.crypto.tink.TinkProtoKeysetFormat.parseEncryptedKeyset(
            keysetBytes,
            kekAead,
            domainAad("EDST_KEYSET_V1", storeName),
        )
        val v012KeysetBytes = com.google.crypto.tink.TinkProtoKeysetFormat.serializeEncryptedKeyset(
            handle,
            kekAead,
            domainAad("EDST_KEYSET_V1", "$storeName:$storeName"),
        )
        FileSystem.SYSTEM.write(storeDir / "$storeName.keyset") { write(v012KeysetBytes) }

        val reopened = MaigSecurityCrypto.create(
            context = testContext { "pass123".toCharArray() },
            config = MaigSecurityConfig(storeName = storeName),
            serializer = AuthSession.serializer(),
            defaultValue = { AuthSession() },
        )
        assertEquals("legacy_012_secret", reopened.get().accessToken)
        reopened.close()
    }

    @Test
    fun `MaigEncryptedPreferences handles all types reactive observation and persistence`() = runTest {
        val prefs = MaigSecurityCrypto.createPreferences(
            context = testContext(),
            config = MaigSecurityConfig(storeName = "prefs_test"),
        )

        val kStr = MaigPreferenceKeys.string("token")
        val kInt = MaigPreferenceKeys.int("count")
        val kLong = MaigPreferenceKeys.long("timestamp")
        val kFloat = MaigPreferenceKeys.float("ratio")
        val kDouble = MaigPreferenceKeys.double("precision")
        val kBool = MaigPreferenceKeys.boolean("biometric_enabled")
        val kSet = MaigPreferenceKeys.stringSet("scopes")
        val kBytes = MaigPreferenceKeys.byteArray("hmac_seed")
        val kProfile = MaigPreferenceKeys.serializable("profile", CustomProfile.serializer())

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

        val reopened = MaigSecurityCrypto.createPreferences(
            context = testContext(),
            config = MaigSecurityConfig(storeName = "prefs_test"),
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
