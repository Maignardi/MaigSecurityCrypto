package io.github.encrypteddatastore

import kotlinx.coroutines.CoroutineScope
import okio.FileSystem
import okio.Path

internal data class EncryptedEnvelopeResult(
    val keyEpoch: Long,
    val envelopeBytes: ByteArray,
)

/**
 * Platform-specific key management and AEAD encryption engine.
 * Implementations MUST synchronize keyset/keystore mutations and never expose raw key material
 * in exceptions or logs.
 */
internal interface KeyManager {
    suspend fun currentEpoch(): Long

    suspend fun keyCreatedAtEpochMs(): Long

    suspend fun writesSinceRotation(): Long

    /**
     * Checks [rotationPolicy] if needed, atomically builds the envelope header from the active
     * algorithm and epoch, computes associated data via [aadBuilder], encrypts [plaintext],
     * and returns the complete serialized envelope bytes.
     */
    suspend fun encryptEnvelope(
        plaintext: ByteArray,
        rotationPolicy: KeyRotationPolicy,
        headerBuilder: (CipherAlgorithm, Long) -> ByteArray,
        aadBuilder: (ByteArray) -> ByteArray,
    ): EncryptedEnvelopeResult

    suspend fun decrypt(
        ciphertext: ByteArray,
        algorithm: CipherAlgorithm,
        keyEpoch: Long,
        associatedData: ByteArray,
    ): ByteArray

    /**
     * Unconditionally promotes a new primary key, increments the key epoch, and trims retained
     * historical keys according to [maxRetainedKeys] (minimum 2).
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

internal expect fun defaultCipherAlgorithm(): CipherAlgorithm
