package io.github.encrypteddatastore

import androidx.datastore.core.DataStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.job
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import okio.FileSystem
import okio.Path

/**
 * A type-safe, encrypted DataStore backed by AEAD envelope encryption, hardware-backed key management,
 * AAD domain binding, and key rotation.
 */
public class EncryptedDataStore<T> internal constructor(
    private val internalStore: DataStore<EncryptedBox<T>>,
    private val keyManager: KeyManager,
    private val config: SecurityConfig,
    private val fileSystem: FileSystem,
    private val filePath: Path,
    private val storeScope: CoroutineScope,
    private val defaultValueProvider: () -> T,
) {
    private val operationMutex = Mutex()

    /**
     * Reactive stream of decrypted values.
     */
    public val data: Flow<T> = internalStore.data
        .map { it.value }
        .distinctUntilChanged()

    /**
     * Atomically reads, transforms, and writes the encrypted state.
     * Automatically triggers key rotation before writing if configured by [SecurityConfig.keyRotationPolicy].
     */
    public suspend fun updateData(transform: suspend (t: T) -> T): T {
        return operationMutex.withLock {
            val activeEpoch = keyManager.rotateIfPolicyRequires(config.keyRotationPolicy)
            val updated = internalStore.updateData { box ->
                val newValue = transform(box.value)
                EncryptedBox(value = newValue, keyEpoch = activeEpoch)
            }
            enforceRestrictiveFilePermissions(fileSystem, filePath)
            updated.value
        }
    }

    /**
     * Reads the current value once.
     */
    public suspend fun get(): T = data.first()

    /**
     * Explicitly rotates the active Data Encryption Key (DEK) and atomically re-encrypts
     * the persisted store under the new key epoch.
     *
     * @return The new active key epoch.
     */
    public suspend fun rotateKeys(): Long {
        return operationMutex.withLock {
            val maxRetained = when (val policy = config.keyRotationPolicy) {
                KeyRotationPolicy.Manual -> 2
                is KeyRotationPolicy.Automatic -> policy.maxRetainedKeys.coerceAtLeast(2)
            }
            val newEpoch = keyManager.rotateKey(maxRetainedKeys = maxRetained, trigger = "manual")
            internalStore.updateData { box ->
                box.copy(keyEpoch = newEpoch)
            }
            enforceRestrictiveFilePermissions(fileSystem, filePath)
            newEpoch
        }
    }

    /**
     * Destroys all persisted data, resets the store to its default value, and destroys all
     * historical encryption keys so prior ciphertexts cannot be recovered.
     */
    public suspend fun clearAndReset() {
        operationMutex.withLock {
            val newEpoch = keyManager.rotateKey(maxRetainedKeys = 2, trigger = "clear_and_reset")
            internalStore.updateData {
                EncryptedBox(value = defaultValueProvider(), keyEpoch = newEpoch)
            }
            keyManager.pruneHistoricalKeys()
            enforceRestrictiveFilePermissions(fileSystem, filePath)
        }
    }

    /**
     * Returns non-sensitive security posture diagnostics for auditing or debug panels.
     */
    public suspend fun diagnostics(): SecurityDiagnostics = keyManager.diagnostics()

    /**
     * Cancels this store's internal coroutine scope and waits for DataStore to release
     * its active file lock so the same store path can be reopened cleanly if needed.
     */
    public suspend fun close() {
        storeScope.coroutineContext.job.cancelAndJoin()
    }
}
