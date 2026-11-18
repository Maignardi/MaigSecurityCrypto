package io.github.maigsecuritycrypto

import com.google.crypto.tink.Aead
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
import java.io.FileOutputStream
import java.nio.channels.FileChannel
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermissions
import java.security.GeneralSecurityException
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
    private val context: MaigStorageContext,
    private val config: MaigSecurityConfig,
) : KeyManager {

    companion object {
        private val tinkRegistered: Boolean by lazy {
            AeadConfig.register()
            true
        }
        private const val PBKDF2_ITERATIONS = 310_000
        private const val SALT_BYTES = 32
        private const val KEK_BYTES = 32
        private const val META_CHECKPOINT_INTERVAL = 10L
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

    private var cachedKekAead: Aead? = null
    private var cachedHandle: KeysetHandle? = null
    private var cachedAead: Aead? = null
    private var cachedMetadata: KeyRotationMetadata? = null

    private val securityLevel: MaigSecurityLevel =
        if (context.masterPassphraseProvider != null) {
            MaigSecurityLevel.PASSPHRASE_PBKDF2
        } else {
            MaigSecurityLevel.LOCAL_FILE_KEK
        }

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

    override suspend fun encryptEnvelope(
        plaintext: ByteArray,
        rotationPolicy: MaigKeyRotationPolicy,
        headerBuilder: (MaigCipherAlgorithm, Long) -> ByteArray,
        aadBuilder: (ByteArray) -> ByteArray,
    ): EncryptedEnvelopeResult = mutex.withLock {
        ensureInitializedLocked()
        rotateIfPolicyRequiresLocked(rotationPolicy)
        val aead = cachedAead!!
        val meta = cachedMetadata!!
        val header = headerBuilder(config.algorithm, meta.epoch)
        val aad = aadBuilder(header)
        val ciphertext = try {
            aead.encrypt(plaintext, aad)
        } catch (e: GeneralSecurityException) {
            throw MaigEncryptionException("AEAD encryption failed for '${config.storeName}'", e)
        }
        val updatedMeta = meta.copy(writesSinceRotation = meta.writesSinceRotation + 1L)
        if (shouldPersistMetadataWrite(rotationPolicy, updatedMeta.writesSinceRotation)) {
            persistMetadataLocked(aead, updatedMeta)
        }
        cachedMetadata = updatedMeta
        EncryptedEnvelopeResult(
            keyEpoch = meta.epoch,
            envelopeBytes = EncryptedEnvelopeCodec.encode(header, ciphertext),
        )
    }

    override suspend fun decrypt(
        ciphertext: ByteArray,
        algorithm: MaigCipherAlgorithm,
        keyEpoch: Long,
        associatedData: ByteArray,
    ): ByteArray = mutex.withLock {
        ensureInitializedLocked()
        val aead = cachedAead!!
        try {
            aead.decrypt(ciphertext, associatedData)
        } catch (e: GeneralSecurityException) {
            throw MaigStoreTamperedOrCorruptedException(
                "AEAD authentication failed for '${config.storeName}' (epoch=$keyEpoch, alg=$algorithm)",
                e,
            )
        }
    }

    override suspend fun rotateKey(maxRetainedKeys: Int, trigger: String): Long = mutex.withLock {
        ensureInitializedLocked()
        rotateKeyLocked(maxRetainedKeys.coerceAtLeast(2), trigger)
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
        destroyKeyMaterialLocked()
        val nextEpoch = (previousEpoch + 1L).coerceAtLeast(1L)
        initializeFreshLocked(initialEpoch = nextEpoch)
        nextEpoch
    }

    override suspend fun destroyKeyMaterial() {
        mutex.withLock {
            destroyKeyMaterialLocked()
        }
    }

    private fun destroyKeyMaterialLocked() {
        context.fileSystem.delete(keysetPath, mustExist = false)
        context.fileSystem.delete(metadataPath, mustExist = false)
        context.fileSystem.delete(kekSaltOrSecretPath, mustExist = false)
        cachedKekAead = null
        cachedHandle = null
        cachedAead = null
        cachedMetadata = null
    }

    override suspend fun diagnostics(): MaigSecurityDiagnostics = mutex.withLock {
        ensureInitializedLocked()
        val meta = cachedMetadata!!
        MaigSecurityDiagnostics(
            storeName = config.storeName,
            algorithm = config.algorithm,
            securityLevel = securityLevel,
            currentKeyEpoch = meta.epoch,
            keyCreatedAtEpochMs = meta.createdAtEpochMs,
            writesSinceRotation = meta.writesSinceRotation,
            hardwareBacked = false,
        )
    }

    private fun shouldPersistMetadataWrite(policy: MaigKeyRotationPolicy, writes: Long): Boolean {
        if (policy !is MaigKeyRotationPolicy.Automatic) return false
        return policy.maxWritesBeforeRotation < META_CHECKPOINT_INTERVAL * 2 ||
            writes % META_CHECKPOINT_INTERVAL == 0L
    }

    private fun rotateIfPolicyRequiresLocked(policy: MaigKeyRotationPolicy) {
        if (policy !is MaigKeyRotationPolicy.Automatic) return
        val meta = cachedMetadata!!
        val nowMs = System.currentTimeMillis()
        val ageMs = (nowMs - meta.createdAtEpochMs).coerceAtLeast(0L)
        val maxAgeMs = policy.maxKeyAge.toLong(DurationUnit.MILLISECONDS)
        val trigger = when {
            meta.writesSinceRotation >= policy.maxWritesBeforeRotation -> "write_limit"
            ageMs >= maxAgeMs -> "max_age"
            else -> null
        }
        if (trigger != null) {
            rotateKeyLocked(policy.maxRetainedKeys.coerceAtLeast(2), trigger)
        }
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
        val kekAead = deriveOrLoadKekAeadLocked(createIfMissing = true)
        val handle = KeysetHandle.generateNew(keyTemplateFor(config.algorithm))
        val aead = handle.getPrimitive(RegistryConfiguration.get(), Aead::class.java)
        val meta = KeyRotationMetadata(
            epoch = initialEpoch,
            createdAtEpochMs = System.currentTimeMillis(),
            writesSinceRotation = 0L,
        )
        persistKeysetWithKekLocked(kekAead, handle)
        persistMetadataLocked(aead, meta)
        cachedKekAead = kekAead
        cachedHandle = handle
        cachedAead = aead
        cachedMetadata = meta
        config.eventListener?.onEvent(
            MaigSecurityEvent.KeyInitialized(
                storeName = config.storeName,
                securityLevel = securityLevel,
                epoch = meta.epoch,
            )
        )
    }

    private fun loadExistingLocked() {
        val kekAead = deriveOrLoadKekAeadLocked(createIfMissing = false)
        val encryptedBytes = readBytes(keysetPath)
        var migratedFromV012Aad = false
        val handle = try {
            TinkProtoKeysetFormat.parseEncryptedKeyset(
                encryptedBytes,
                kekAead,
                keysetAssociatedData(),
            )
        } catch (primaryError: GeneralSecurityException) {
            // Backward compatibility: 0.1.2 briefly used "storeName:storeName" as JVM AAD.
            try {
                TinkProtoKeysetFormat.parseEncryptedKeyset(
                    encryptedBytes,
                    kekAead,
                    legacyV012KeysetAssociatedData(),
                ).also { migratedFromV012Aad = true }
            } catch (_: GeneralSecurityException) {
                // Do NOT cache unvalidated KEK when unwrap fails (e.g., wrong passphrase).
                throw MaigKeyManagementException(
                    "Failed to decrypt keyset for '${config.storeName}'",
                    primaryError,
                )
            }
        }
        val aead = handle.getPrimitive(RegistryConfiguration.get(), Aead::class.java)
        val meta = if (context.fileSystem.exists(metadataPath)) {
            loadMetadataLocked(aead, allowV012Fallback = migratedFromV012Aad)
        } else {
            KeyRotationMetadata(
                epoch = 1L,
                createdAtEpochMs = System.currentTimeMillis(),
                writesSinceRotation = 0L,
            ).also { persistMetadataLocked(aead, it) }
        }
        if (migratedFromV012Aad) {
            persistKeysetWithKekLocked(kekAead, handle)
            persistMetadataLocked(aead, meta)
        }
        cachedKekAead = kekAead
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
            MaigSecurityEvent.KeyRotated(
                storeName = config.storeName,
                oldEpoch = oldMeta.epoch,
                newEpoch = newEpoch,
                trigger = trigger,
            )
        )
        return newEpoch
    }

    private fun persistKeysetLocked(handle: KeysetHandle) {
        val kekAead = deriveOrLoadKekAeadLocked(createIfMissing = true)
        persistKeysetWithKekLocked(kekAead, handle)
    }

    private fun persistKeysetWithKekLocked(kekAead: Aead, handle: KeysetHandle) {
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

    private fun loadMetadataLocked(aead: Aead, allowV012Fallback: Boolean = false): KeyRotationMetadata {
        val encrypted = readBytes(metadataPath)
        val plain = try {
            aead.decrypt(encrypted, metadataAssociatedData())
        } catch (e: GeneralSecurityException) {
            if (allowV012Fallback) {
                try {
                    aead.decrypt(encrypted, legacyV012MetadataAssociatedData())
                } catch (e2: GeneralSecurityException) {
                    throw MaigStoreTamperedOrCorruptedException(
                        "Key rotation metadata authentication failed for '${config.storeName}'",
                        e2,
                    )
                }
            } else {
                throw MaigStoreTamperedOrCorruptedException(
                    "Key rotation metadata authentication failed for '${config.storeName}'",
                    e,
                )
            }
        }
        return try {
            json.decodeFromString(KeyRotationMetadata.serializer(), plain.decodeToString())
        } finally {
            plain.wipe()
        }
    }

    private fun deriveOrLoadKekAeadLocked(createIfMissing: Boolean): Aead {
        cachedKekAead?.let { return it }

        val passphraseProvider = context.masterPassphraseProvider
        return if (passphraseProvider != null) {
            val salt = if (context.fileSystem.exists(kekSaltOrSecretPath)) {
                readBytes(kekSaltOrSecretPath)
            } else {
                if (!createIfMissing) {
                    throw MaigKeyManagementException("Missing KEK salt for '${config.storeName}'")
                }
                ByteArray(SALT_BYTES).also {
                    secureRandom.nextBytes(it)
                    atomicWrite(kekSaltOrSecretPath, it)
                }
            }
            val passphraseCopy = passphraseProvider.invoke().copyOf()
            val derivedKey = try {
                derivePbkdf2Key(passphraseCopy, salt)
            } finally {
                passphraseCopy.fill('\u0000')
            }
            try {
                AesGcmJce(derivedKey)
            } finally {
                derivedKey.wipe()
            }
        } else {
            val secret = if (context.fileSystem.exists(kekSaltOrSecretPath)) {
                readBytes(kekSaltOrSecretPath)
            } else {
                if (!createIfMissing) {
                    throw MaigKeyManagementException("Missing local KEK secret for '${config.storeName}'")
                }
                ByteArray(KEK_BYTES).also {
                    secureRandom.nextBytes(it)
                    atomicWrite(kekSaltOrSecretPath, it)
                }
            }
            try {
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
        if (context.fileSystem !== FileSystem.SYSTEM) {
            context.fileSystem.write(tmp) { write(bytes) }
            context.fileSystem.atomicMove(tmp, target)
            return
        }

        val tmpFile = tmp.toFile()
        val targetFile = target.toFile()
        val tmpNio = tmpFile.toPath()
        val targetNio = targetFile.toPath()

        if (tmpFile.exists()) {
            tmpFile.delete()
        }
        try {
            val perms = PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))
            Files.createFile(tmpNio, perms)
        } catch (_: UnsupportedOperationException) {
            tmpFile.createNewFile()
            enforceRestrictiveFilePermissions(context.fileSystem, tmp)
        }

        FileOutputStream(tmpFile).use { fos ->
            fos.write(bytes)
            fos.flush()
            fos.fd.sync()
        }

        try {
            Files.move(tmpNio, targetNio, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
        } catch (_: AtomicMoveNotSupportedException) {
            Files.move(tmpNio, targetNio, StandardCopyOption.REPLACE_EXISTING)
        }
        enforceRestrictiveFilePermissions(context.fileSystem, target)
        fsyncParentDirectory(targetFile.parentFile?.toPath())
    }

    private fun fsyncParentDirectory(dirPath: java.nio.file.Path?) {
        if (dirPath == null) return
        runCatching {
            FileChannel.open(dirPath, StandardOpenOption.READ).use { it.force(true) }
        }
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

    private fun legacyV012KeysetAssociatedData(): ByteArray =
        buildDomainAad(KEYSET_AAD_TAG, "${config.storeName}:${config.storeName}")

    private fun legacyV012MetadataAssociatedData(): ByteArray =
        buildDomainAad(METADATA_AAD_TAG, "${config.storeName}:${config.storeName}")

    private fun buildDomainAad(domain: ByteArray, scope: String): ByteArray {
        val scopeBytes = scope.encodeToByteArray()
        return Buffer().apply {
            writeInt(domain.size)
            write(domain)
            writeInt(scopeBytes.size)
            write(scopeBytes)
        }.readByteArray()
    }

    private fun keyTemplateFor(algorithm: MaigCipherAlgorithm) =
        KeyTemplates.get(tinkParameterName(algorithm))

    private fun tinkParameterName(algorithm: MaigCipherAlgorithm): String = when (algorithm) {
        MaigCipherAlgorithm.AES256_GCM -> "AES256_GCM"
        MaigCipherAlgorithm.XCHACHA20_POLY1305 -> "XCHACHA20_POLY1305"
        MaigCipherAlgorithm.AES256_CTR_HMAC_SHA256 -> "AES256_CTR_HMAC_SHA256"
    }
}
