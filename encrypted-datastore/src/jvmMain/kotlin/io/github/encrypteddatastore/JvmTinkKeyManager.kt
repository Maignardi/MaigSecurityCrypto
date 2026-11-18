package io.github.encrypteddatastore

import com.google.crypto.tink.Aead
import com.google.crypto.tink.InsecureSecretKeyAccess
import com.google.crypto.tink.KeyStatus
import com.google.crypto.tink.KeyTemplates
import com.google.crypto.tink.KeysetHandle
import com.google.crypto.tink.RegistryConfiguration
import com.google.crypto.tink.TinkProtoKeysetFormat
import com.google.crypto.tink.aead.AeadConfig
import com.google.crypto.tink.subtle.AesGcmJce
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import okio.Buffer
import okio.FileSystem
import okio.Path
import java.security.GeneralSecurityException
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import kotlin.time.DurationUnit

@Serializable
internal data class KeyRotationMetadata(
    val epoch: Long,
    val createdAtEpochMs: Long,
    val writesSinceRotation: Long,
)

internal class JvmTinkKeyManager(
    private val context: PlatformStorageContext,
    private val config: SecurityConfig,
) : KeyManager {

    companion object {
        private val tinkRegistered: Boolean by lazy {
            AeadConfig.register()
            true
        }
        private const val PBKDF2_ITERATIONS = 310_000
        private const val SALT_BYTES = 32
        private const val KEK_BYTES = 32
        private val METADATA_AAD_TAG = "EDST_META_V1".encodeToByteArray()
        private val KEYSET_AAD_TAG = "EDST_KEYSET_V1".encodeToByteArray()
    }

    private val mutex = Mutex()
    private val secureRandom = SecureRandom()
    private val json = Json { ignoreUnknownKeys = true }

    private val storeDir: Path = context.storageDirectory / "encrypted_datastore"
    private val keysetPath: Path = storeDir / "${config.storeName}.keyset"
    private val kekSaltOrSecretPath: Path = storeDir / "${config.storeName}.kek"
    private val metadataPath: Path = storeDir / "${config.storeName}.meta"

    private var cachedHandle: KeysetHandle? = null
    private var cachedAead: Aead? = null
    private var cachedMetadata: KeyRotationMetadata? = null

    override val securityLevel: SecurityLevel =
        if (context.masterPassphraseProvider != null) SecurityLevel.JVM_KEYSTORE else SecurityLevel.SOFTWARE_FALLBACK

    override suspend fun currentEpoch(): Long = mutex.withLock {
        ensureInitializedLocked()
        cachedMetadata!!.epoch
    }

    override suspend fun keyCreatedAtEpochMs(): Long = mutex.withLock {
        ensureInitializedLocked()
        cachedMetadata!!.createdAtEpochMs
    }

    override suspend fun writesSinceRotation(): Long = mutex.withLock {
        ensureInitializedLocked()
        cachedMetadata!!.writesSinceRotation
    }

    override suspend fun encrypt(plaintext: ByteArray, associatedData: ByteArray): EncryptedPayload =
        mutex.withLock {
            ensureInitializedLocked()
            val aead = cachedAead!!
            val meta = cachedMetadata!!
            val ciphertext = try {
                aead.encrypt(plaintext, associatedData)
            } catch (e: GeneralSecurityException) {
                throw EncryptionException("AEAD encryption failed for '${config.storeName}'", e)
            }
            val updatedMeta = meta.copy(writesSinceRotation = meta.writesSinceRotation + 1L)
            persistMetadataLocked(aead, updatedMeta)
            cachedMetadata = updatedMeta
            EncryptedPayload(
                keyEpoch = meta.epoch,
                algorithm = config.algorithm,
                ciphertext = ciphertext,
            )
        }

    override suspend fun decrypt(
        ciphertext: ByteArray,
        algorithm: CipherAlgorithm,
        keyEpoch: Long,
        associatedData: ByteArray,
    ): ByteArray = mutex.withLock {
        ensureInitializedLocked()
        val aead = cachedAead!!
        try {
            aead.decrypt(ciphertext, associatedData)
        } catch (e: GeneralSecurityException) {
            throw StoreTamperedOrCorruptedException(
                "AEAD authentication failed for '${config.storeName}' (epoch=$keyEpoch, alg=$algorithm)",
                e,
            )
        }
    }

    override suspend fun rotateIfPolicyRequires(policy: KeyRotationPolicy): Long = mutex.withLock {
        ensureInitializedLocked()
        val meta = cachedMetadata!!
        if (policy is KeyRotationPolicy.Automatic) {
            val nowMs = System.currentTimeMillis()
            val ageMs = (nowMs - meta.createdAtEpochMs).coerceAtLeast(0L)
            val maxAgeMs = policy.maxKeyAge.toLong(DurationUnit.MILLISECONDS)
            val trigger = when {
                meta.writesSinceRotation >= policy.maxWritesBeforeRotation -> "write_limit"
                ageMs >= maxAgeMs -> "max_age"
                else -> null
            }
            if (trigger != null) {
                return@withLock rotateKeyLocked(policy.maxRetainedKeys, trigger)
            }
        }
        meta.epoch
    }

    override suspend fun rotateKey(maxRetainedKeys: Int, trigger: String): Long = mutex.withLock {
        ensureInitializedLocked()
        rotateKeyLocked(maxRetainedKeys, trigger)
    }

    override suspend fun pruneHistoricalKeys() {
        mutex.withLock {
            ensureInitializedLocked()
            val currentHandle = cachedHandle!!
            val primaryId = currentHandle.primary.id
            val builder = KeysetHandle.newBuilder(currentHandle)
            for (i in currentHandle.size() - 1 downTo 0) {
                val entry = currentHandle.getAt(i)
                if (entry.id != primaryId) {
                    builder.deleteAt(i)
                }
            }
            val prunedHandle = builder.build()
            persistKeysetLocked(prunedHandle)
            cachedHandle = prunedHandle
            cachedAead = prunedHandle.getPrimitive(RegistryConfiguration.get(), Aead::class.java)
        }
    }

    override suspend fun resetAndRegenerate(reason: String): Long = mutex.withLock {
        check(tinkRegistered)
        val previousEpoch = cachedMetadata?.epoch ?: 0L
        context.fileSystem.delete(keysetPath, mustExist = false)
        context.fileSystem.delete(metadataPath, mustExist = false)
        context.fileSystem.delete(kekSaltOrSecretPath, mustExist = false)
        cachedHandle = null
        cachedAead = null
        cachedMetadata = null

        val nextEpoch = (previousEpoch + 1L).coerceAtLeast(1L)
        initializeFreshLocked(initialEpoch = nextEpoch)
        nextEpoch
    }

    override suspend fun diagnostics(): SecurityDiagnostics = mutex.withLock {
        ensureInitializedLocked()
        val meta = cachedMetadata!!
        SecurityDiagnostics(
            storeName = config.storeName,
            algorithm = config.algorithm,
            securityLevel = securityLevel,
            currentKeyEpoch = meta.epoch,
            keyCreatedAtEpochMs = meta.createdAtEpochMs,
            writesSinceRotation = meta.writesSinceRotation,
            hardwareBacked = false,
        )
    }

    private fun ensureInitializedLocked() {
        check(tinkRegistered)
        if (cachedHandle != null && cachedAead != null && cachedMetadata != null) return

        context.fileSystem.createDirectories(storeDir)
        enforceRestrictiveDirPermissions(storeDir)

        if (context.fileSystem.exists(keysetPath)) {
            loadExistingLocked()
        } else {
            initializeFreshLocked(initialEpoch = 1L)
        }
    }

    private fun initializeFreshLocked(initialEpoch: Long) {
        val handle = KeysetHandle.generateNew(keyTemplateFor(config.algorithm))
        val aead = handle.getPrimitive(RegistryConfiguration.get(), Aead::class.java)
        val meta = KeyRotationMetadata(
            epoch = initialEpoch,
            createdAtEpochMs = System.currentTimeMillis(),
            writesSinceRotation = 0L,
        )
        persistKeysetLocked(handle)
        persistMetadataLocked(aead, meta)
        cachedHandle = handle
        cachedAead = aead
        cachedMetadata = meta
        config.eventListener?.onEvent(
            SecurityEvent.KeyInitialized(
                storeName = config.storeName,
                securityLevel = securityLevel,
                epoch = meta.epoch,
            )
        )
    }

    private fun loadExistingLocked() {
        val kekAead = obtainKekAeadLocked(createIfMissing = false)
        val encryptedBytes = readBytes(keysetPath)
        val handle = try {
            TinkProtoKeysetFormat.parseEncryptedKeyset(
                encryptedBytes,
                kekAead,
                keysetAssociatedData(),
            )
        } catch (e: GeneralSecurityException) {
            throw KeyManagementException("Failed to decrypt keyset for '${config.storeName}'", e)
        }
        val aead = handle.getPrimitive(RegistryConfiguration.get(), Aead::class.java)
        val meta = if (context.fileSystem.exists(metadataPath)) {
            loadMetadataLocked(aead)
        } else {
            KeyRotationMetadata(
                epoch = 1L,
                createdAtEpochMs = System.currentTimeMillis(),
                writesSinceRotation = 0L,
            ).also { persistMetadataLocked(aead, it) }
        }
        cachedHandle = handle
        cachedAead = aead
        cachedMetadata = meta
    }

    private fun rotateKeyLocked(maxRetainedKeys: Int, trigger: String): Long {
        val oldHandle = cachedHandle!!
        val oldMeta = cachedMetadata!!
        val builder = KeysetHandle.newBuilder(oldHandle)
        val newEntry = KeysetHandle.generateEntryFromParametersName(tinkParameterName(config.algorithm))
            .withRandomId()
            .makePrimary()
        builder.addEntry(newEntry)

        // Trim oldest entries beyond maxRetainedKeys while preserving the newly added primary.
        var provisional = builder.build()
        if (provisional.size() > maxRetainedKeys) {
            val primaryId = provisional.primary.id
            val trimBuilder = KeysetHandle.newBuilder(provisional)
            var remaining = provisional.size()
            for (i in 0 until provisional.size()) {
                if (remaining <= maxRetainedKeys) break
                val entry = provisional.getAt(i)
                if (entry.id != primaryId) {
                    trimBuilder.deleteAt(i - (provisional.size() - remaining))
                    remaining--
                }
            }
            provisional = trimBuilder.build()
        }

        val newAead = provisional.getPrimitive(RegistryConfiguration.get(), Aead::class.java)
        val newEpoch = oldMeta.epoch + 1L
        val newMeta = KeyRotationMetadata(
            epoch = newEpoch,
            createdAtEpochMs = System.currentTimeMillis(),
            writesSinceRotation = 0L,
        )
        persistKeysetLocked(provisional)
        persistMetadataLocked(newAead, newMeta)
        cachedHandle = provisional
        cachedAead = newAead
        cachedMetadata = newMeta
        config.eventListener?.onEvent(
            SecurityEvent.KeyRotated(
                storeName = config.storeName,
                oldEpoch = oldMeta.epoch,
                newEpoch = newEpoch,
                trigger = trigger,
            )
        )
        return newEpoch
    }

    private fun persistKeysetLocked(handle: KeysetHandle) {
        val kekAead = obtainKekAeadLocked(createIfMissing = true)
        val serialized = TinkProtoKeysetFormat.serializeEncryptedKeyset(
            handle,
            kekAead,
            keysetAssociatedData(),
        )
        try {
            atomicWrite(keysetPath, serialized)
        } finally {
            serialized.wipe()
        }
    }

    private fun persistMetadataLocked(aead: Aead, meta: KeyRotationMetadata) {
        val plain = json.encodeToString(KeyRotationMetadata.serializer(), meta).encodeToByteArray()
        try {
            val encrypted = aead.encrypt(plain, metadataAssociatedData())
            atomicWrite(metadataPath, encrypted)
        } finally {
            plain.wipe()
        }
    }

    private fun loadMetadataLocked(aead: Aead): KeyRotationMetadata {
        val encrypted = readBytes(metadataPath)
        val plain = try {
            aead.decrypt(encrypted, metadataAssociatedData())
        } catch (e: GeneralSecurityException) {
            throw StoreTamperedOrCorruptedException(
                "Key rotation metadata authentication failed for '${config.storeName}'",
                e,
            )
        }
        return try {
            json.decodeFromString(KeyRotationMetadata.serializer(), plain.decodeToString())
        } finally {
            plain.wipe()
        }
    }

    private fun obtainKekAeadLocked(createIfMissing: Boolean): Aead {
        val passphraseProvider = context.masterPassphraseProvider
        if (passphraseProvider != null) {
            val salt = if (context.fileSystem.exists(kekSaltOrSecretPath)) {
                readBytes(kekSaltOrSecretPath)
            } else {
                if (!createIfMissing) {
                    throw KeyManagementException("Missing KEK salt for '${config.storeName}'")
                }
                ByteArray(SALT_BYTES).also {
                    secureRandom.nextBytes(it)
                    atomicWrite(kekSaltOrSecretPath, it)
                }
            }
            val passphrase = passphraseProvider.invoke()
            val derivedKey = derivePbkdf2Key(passphrase, salt)
            passphrase.fill('\u0000')
            return try {
                AesGcmJce(derivedKey)
            } finally {
                derivedKey.wipe()
            }
        } else {
            val secret = if (context.fileSystem.exists(kekSaltOrSecretPath)) {
                readBytes(kekSaltOrSecretPath)
            } else {
                if (!createIfMissing) {
                    throw KeyManagementException("Missing local KEK secret for '${config.storeName}'")
                }
                ByteArray(KEK_BYTES).also {
                    secureRandom.nextBytes(it)
                    atomicWrite(kekSaltOrSecretPath, it)
                }
            }
            return try {
                AesGcmJce(secret)
            } finally {
                secret.wipe()
            }
        }
    }

    private fun derivePbkdf2Key(passphrase: CharArray, salt: ByteArray): ByteArray {
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val spec = PBEKeySpec(passphrase, salt, PBKDF2_ITERATIONS, KEK_BYTES * 8)
        return try {
            factory.generateSecret(spec).encoded
        } finally {
            spec.clearPassword()
        }
    }

    private fun atomicWrite(target: Path, bytes: ByteArray) {
        val tmp = target.parent!! / "${target.name}.tmp"
        context.fileSystem.write(tmp) {
            write(bytes)
        }
        enforceRestrictiveFilePermissions(context.fileSystem, tmp)
        context.fileSystem.atomicMove(tmp, target)
        enforceRestrictiveFilePermissions(context.fileSystem, target)
    }

    private fun readBytes(path: Path): ByteArray {
        return context.fileSystem.read(path) {
            readByteArray()
        }
    }

    private fun keysetAssociatedData(): ByteArray =
        buildDomainAad(KEYSET_AAD_TAG, config.storeName)

    private fun metadataAssociatedData(): ByteArray =
        buildDomainAad(METADATA_AAD_TAG, config.storeName)

    private fun buildDomainAad(domain: ByteArray, storeName: String): ByteArray {
        val storeBytes = storeName.encodeToByteArray()
        return Buffer().apply {
            writeInt(domain.size)
            write(domain)
            writeInt(storeBytes.size)
            write(storeBytes)
        }.readByteArray()
    }

    private fun keyTemplateFor(algorithm: CipherAlgorithm) =
        KeyTemplates.get(tinkParameterName(algorithm))

    private fun tinkParameterName(algorithm: CipherAlgorithm): String = when (algorithm) {
        CipherAlgorithm.AES256_GCM -> "AES256_GCM"
        CipherAlgorithm.XCHACHA20_POLY1305 -> "XCHACHA20_POLY1305"
    }
}
