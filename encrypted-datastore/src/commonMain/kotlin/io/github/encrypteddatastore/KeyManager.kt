package io.github.encrypteddatastore

import kotlinx.coroutines.CoroutineScope
import okio.FileSystem
import okio.Path

internal data class EncryptedPayload(
    val keyEpoch: Long,
    val algorithm: CipherAlgorithm,
    val ciphertext: ByteArray,
)

/**
 * Platform-specific key management and AEAD encryption engine.
 * Implementations MUST synchronize keyset/keystore mutations and never expose raw key material
 * in exceptions or logs.
 */
internal interface KeyManager {
    val securityLevel: SecurityLevel

    suspend fun currentEpoch(): Long

    suspend fun keyCreatedAtEpochMs(): Long

    suspend fun writesSinceRotation(): Long

    suspend fun encrypt(plaintext: ByteArray, associatedData: ByteArray): EncryptedPayload

    suspend fun decrypt(
        ciphertext: ByteArray,
        algorithm: CipherAlgorithm,
        keyEpoch: Long,
        associatedData: ByteArray,
    ): ByteArray

    /**
     * Checks [KeyRotationPolicy] and rotates the primary key if needed.
     * Returns the resulting active epoch.
     */
    suspend fun rotateIfPolicyRequires(policy: KeyRotationPolicy): Long

    /**
     * Unconditionally promotes a new primary key, increments the key epoch, and trims retained
     * historical keys according to [maxRetainedKeys].
     */
    suspend fun rotateKey(maxRetainedKeys: Int, trigger: String = "manual"): Long

    /**
     * Destroys all historical non-primary keys so old ciphertexts can no longer be decrypted.
     */
    suspend fun pruneHistoricalKeys()

    /**
     * Atomically destroys existing key material and generates a fresh keyset/epoch.
     */
    suspend fun resetAndRegenerate(reason: String): Long

    suspend fun diagnostics(): SecurityDiagnostics
}

/**
 * Platform-specific storage context holding where encrypted DataStore files and keysets live.
 */
public expect class PlatformStorageContext

internal expect fun createPlatformKeyManager(
    context: PlatformStorageContext,
    config: SecurityConfig,
): KeyManager

internal expect fun resolveEncryptedStoreFile(
    context: PlatformStorageContext,
    config: SecurityConfig,
): Pair<FileSystem, Path>

internal expect fun enforceRestrictiveFilePermissions(
    fileSystem: FileSystem,
    path: Path,
)

internal expect fun defaultIoCoroutineScope(): CoroutineScope
