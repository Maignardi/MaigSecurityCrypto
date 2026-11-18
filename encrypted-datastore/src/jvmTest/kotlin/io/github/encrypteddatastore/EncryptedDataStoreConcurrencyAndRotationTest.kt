package io.github.encrypteddatastore

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.delay
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
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.milliseconds

@Serializable
data class CounterState(val count: Int = 0, val history: List<Int> = emptyList())

class EncryptedDataStoreConcurrencyAndRotationTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    private fun testContext() = PlatformStorageContext(
        storageDirectory = tempFolder.root.toOkioPath(),
        fileSystem = FileSystem.SYSTEM,
    )

    private fun storeFilePath(storeName: String) =
        tempFolder.root.toOkioPath() / "encrypted_datastore" / "$storeName.edst"

    @Test
    fun `handles 50 concurrent writers without lost updates or corruption`() = runTest {
        val store = EncryptedDataStoreFactory.create(
            context = testContext(),
            config = SecurityConfig(
                storeName = "concurrency_store",
                keyRotationPolicy = KeyRotationPolicy.Automatic(
                    maxKeyAge = 30.days,
                    maxWritesBeforeRotation = 15L,
                    maxRetainedKeys = 2,
                ),
            ),
            serializer = CounterState.serializer(),
            defaultValue = { CounterState() },
        )

        val jobs = (1..50).map { idx ->
            async(Dispatchers.Default) {
                store.updateData { current ->
                    current.copy(
                        count = current.count + 1,
                        history = current.history + idx,
                    )
                }
            }
        }
        jobs.awaitAll()

        val finalState = store.get()
        assertEquals(50, finalState.count)
        assertEquals(50, finalState.history.size)
        assertEquals((1..50).toSet(), finalState.history.toSet())
        assertTrue(store.diagnostics().currentKeyEpoch >= 3L)
        store.close()
    }

    @Test
    fun `prunes keys beyond maxRetainedKeys so very old ciphertext snapshots become unreadable`() = runTest {
        val store = EncryptedDataStoreFactory.create(
            context = testContext(),
            config = SecurityConfig(
                storeName = "prune_test",
                keyRotationPolicy = KeyRotationPolicy.Automatic(
                    maxKeyAge = 30.days,
                    maxWritesBeforeRotation = 100L,
                    maxRetainedKeys = 2,
                ),
            ),
            serializer = AuthSession.serializer(),
            defaultValue = { AuthSession() },
        )

        // Write under epoch 1 and capture disk snapshot
        store.updateData { AuthSession(accessToken = "epoch_1_secret") }
        val epoch1Snapshot = FileSystem.SYSTEM.read(storeFilePath("prune_test")) { readByteArray() }

        // Rotate 3 times with maxRetainedKeys = 2 -> epochs kept should be 3 and 4; epoch 1 pruned!
        assertEquals(2L, store.rotateKeys())
        assertEquals(3L, store.rotateKeys())
        assertEquals(4L, store.rotateKeys())
        assertEquals("epoch_1_secret", store.get().accessToken)
        store.close()

        // Replace current file with old epoch-1 snapshot: must fail authentication because key 1 was pruned
        FileSystem.SYSTEM.write(storeFilePath("prune_test")) { write(epoch1Snapshot) }
        val reopened = EncryptedDataStoreFactory.create(
            context = testContext(),
            config = SecurityConfig(
                storeName = "prune_test",
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
    fun `automatic key rotation triggers when maxKeyAge expires`() = runTest {
        val events = mutableListOf<SecurityEvent>()
        val store = EncryptedDataStoreFactory.create(
            context = testContext(),
            config = SecurityConfig(
                storeName = "age_rotation",
                keyRotationPolicy = KeyRotationPolicy.Automatic(
                    maxKeyAge = 15.milliseconds,
                    maxWritesBeforeRotation = 10_000L,
                    maxRetainedKeys = 2,
                ),
                eventListener = { events += it },
            ),
            serializer = AuthSession.serializer(),
            defaultValue = { AuthSession() },
        )

        store.updateData { AuthSession(accessToken = "initial") }
        assertEquals(1L, store.diagnostics().currentKeyEpoch)

        Thread.sleep(40L)

        store.updateData { AuthSession(accessToken = "after_expiry") }
        assertEquals(2L, store.diagnostics().currentKeyEpoch)
        assertTrue(events.any { it is SecurityEvent.KeyRotated && it.trigger == "max_age" })
        store.close()
    }

    @Test
    fun `EncryptedPreferences edge cases null removal clear type safety and empty byte arrays`() = runTest {
        val prefs = EncryptedDataStoreFactory.createPreferences(
            context = testContext(),
            config = SecurityConfig(storeName = "prefs_edge"),
        )

        val strKey = PreferenceKeys.string("shared_name")
        val intWithSameName = PreferenceKeys.int("shared_name")
        val bytesKey = PreferenceKeys.byteArray("empty_bytes")

        prefs.edit {
            it[strKey] = "hello"
            it[bytesKey] = ByteArray(0)
        }

        // Reading a key with a mismatched type must safely return null, not throw ClassCastException
        assertNull(prefs.get(intWithSameName))
        assertEquals("hello", prefs.get(strKey))
        assertContentEquals(ByteArray(0), prefs.get(bytesKey))

        // Assigning null removes the key
        prefs.edit { it[strKey] = null }
        assertFalse(prefs.contains(strKey))

        // clear() empties all entries
        prefs.edit { it.clear() }
        assertFalse(prefs.contains(bytesKey))

        prefs.close()
    }

    @Test
    fun `security events never contain sensitive plaintext`() = runTest {
        val secret = "ULTRA_SENSITIVE_TOKEN_XYZ_999"
        val events = mutableListOf<SecurityEvent>()
        val store = EncryptedDataStoreFactory.create(
            context = testContext(),
            config = SecurityConfig(
                storeName = "audit_events",
                eventListener = { events += it },
            ),
            serializer = AuthSession.serializer(),
            defaultValue = { AuthSession() },
        )

        store.updateData { AuthSession(accessToken = secret) }
        store.rotateKeys()

        assertTrue(events.isNotEmpty())
        assertTrue(events.none { it.toString().contains(secret) })
        store.close()
    }
}
