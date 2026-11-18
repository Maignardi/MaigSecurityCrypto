package io.github.encrypteddatastore

import com.google.crypto.tink.Aead
import com.google.crypto.tink.KeyTemplates
import com.google.crypto.tink.KeysetHandle
import com.google.crypto.tink.RegistryConfiguration
import com.google.crypto.tink.TinkProtoKeysetFormat
import com.google.crypto.tink.aead.AeadConfig
import com.google.crypto.tink.subtle.AesGcmJce
import com.google.crypto.tink.subtle.Hkdf
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import okio.Buffer
import java.io.File
import java.io.FileOutputStream
import java.nio.channels.FileChannel
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermissions
import java.security.GeneralSecurityException
import java.security.SecureRandom
import kotlin.time.DurationUnit

@Serializable
internal data class AndroidKeyRotationMetadata(
    val epoch: Long,
    val createdAtEpochMs: Long,
    val writesSinceRotation: Long,
)

/**
 * Android KeyManager combining Google Tink DEK keysets with an [AndroidKeyStoreAead] KEK
 * stored in `noBackupFilesDir` with atomic writes, 0600 permissions, key rotation, and explicit
 * OEM Keystore failure policies.
 *
 * Note: When [SecurityConfig.userAuthConfig] is configured, the DEK keyset is NOT cached in RAM
 * across operations so AndroidKeyStore's authentication validity timeout is enforced on each access.
 */
internal class AndroidTinkKeyManager(
    private val context: PlatformStorageContext,
    private val config: SecurityConfig,
) : KeyManager {

    companion object {
        private val tinkRegistered: Boolean by lazy {
            AeadConfig.register()
            true
        }
        private val KEYSET_AAD_TAG = "EDST_ANDROID_KEYSET_V1".encodeToByteArray()
        private val METADATA_AAD_TAG = "EDST_ANDROID_META_V1".encodeToByteArray()
        private const val SOFTWARE_SECRET_BYTES = 32
    }

    private val mutex = Mutex()
    private val secureRandom = SecureRandom()
    private val json = Json { ignoreUnknownKeys = true }

    private val storeDir: File = resolveAndroidStoreDirectory(context)
    private val keysetFile = File(storeDir, "${config.storeName}.keyset")
    private val metadataFile = File(storeDir, "${config.storeName}.meta")
    private val softwareSecretFile = File(storeDir, "${config.storeName}.swkek")

    private val hardwareKekAead = AndroidKeyStoreAead(context.applicationContext, config)
    private val shouldCacheDekInMemory: Boolean = config.userAuthConfig == null

    private var activeKekAead: Aead? = null
    private var cachedHandle: KeysetHandle? = null
    private var cachedAead: Aead? = null
    private var cachedMetadata: AndroidKeyRotationMetadata? = null
    private var currentSecurityLevel: SecurityLevel = SecurityLevel.UNKNOWN

    private data class UnlockedState(
        val kek: Aead,
        val handle: KeysetHandle,
        val aead: Aead,
        val meta: AndroidKeyRotationMetadata,
        val level: SecurityLevel,
    )

    override suspend fun currentEpoch(): Long = mutex.withLock {
        obtainUnlockedStateLocked().meta.epoch
    }

    override suspend fun keyCreatedAtEpochMs(): Long = mutex.withLock {
        obtainUnlockedStateLocked().meta.createdAtEpochMs
    }

    override suspend fun writesSinceRotation(): Long = mutex.withLock {
        obtainUnlockedStateLocked().meta.writesSinceRotation
    }

    override suspend fun encryptEnvelope(
        plaintext: ByteArray,
        headerBuilder: (CipherAlgorithm, Long) -> ByteArray,
        aadBuilder: (ByteArray) -> ByteArray,
    ): EncryptedEnvelopeResult = mutex.withLock {
        val state = obtainUnlockedStateLocked()
        val header = headerBuilder(config.algorithm, state.meta.epoch)
        val aad = aadBuilder(header)
        val ciphertext = try {
            state.aead.encrypt(plaintext, aad)
        } catch (e: GeneralSecurityException) {
            throw EncryptionException("AEAD encryption failed for '${config.storeName}'", e)
        }
        val updatedMeta = state.meta.copy(writesSinceRotation = state.meta.writesSinceRotation + 1L)
        if (config.keyRotationPolicy is KeyRotationPolicy.Automatic) {
            persistMetadataLocked(state.aead, updatedMeta)
        }
        cachedMetadata = updatedMeta
        EncryptedEnvelopeResult(
            keyEpoch = state.meta.epoch,
            envelopeBytes = EncryptedEnvelopeCodec.encode(header, ciphertext),
        )
    }

    override suspend fun decrypt(
        ciphertext: ByteArray,
        algorithm: CipherAlgorithm,
        keyEpoch: Long,
        associatedData: ByteArray,
    ): ByteArray = mutex.withLock {
        val state = obtainUnlockedStateLocked()
        try {
            state.aead.decrypt(ciphertext, associatedData)
        } catch (e: GeneralSecurityException) {
            throw StoreTamperedOrCorruptedException(
                "AEAD authentication failed for '${config.storeName}' (epoch=$keyEpoch, alg=$algorithm)",
                e,
            )
        }
    }

    override suspend fun rotateIfPolicyRequires(policy: KeyRotationPolicy): Long = mutex.withLock {
        val state = obtainUnlockedStateLocked()
        if (policy is KeyRotationPolicy.Automatic) {
            val nowMs = System.currentTimeMillis()
            val ageMs = (nowMs - state.meta.createdAtEpochMs).coerceAtLeast(0L)
            val maxAgeMs = policy.maxKeyAge.toLong(DurationUnit.MILLISECONDS)
            val trigger = when {
                state.meta.writesSinceRotation >= policy.maxWritesBeforeRotation -> "write_limit"
                ageMs >= maxAgeMs -> "max_age"
                else -> null
            }
            if (trigger != null) {
                return@withLock rotateKeyLocked(state, policy.maxRetainedKeys.coerceAtLeast(2), trigger)
            }
        }
        state.meta.epoch
    }

    override suspend fun rotateKey(maxRetainedKeys: Int, trigger: String): Long = mutex.withLock {
        val state = obtainUnlockedStateLocked()
        rotateKeyLocked(state, maxRetainedKeys.coerceAtLeast(2), trigger)
    }

    override suspend fun pruneHistoricalKeys() {
        mutex.withLock {
            val state = obtainUnlockedStateLocked()
            val primaryId = state.handle.primary.id
            val builder = KeysetHandle.newBuilder(state.handle)
            for (i in state.handle.size() - 1 downTo 0) {
                if (state.handle.getAt(i).id != primaryId) {
                    builder.deleteAt(i)
                }
            }
            val prunedHandle = builder.build()
            persistKeysetLocked(state.kek, prunedHandle)
            if (shouldCacheDekInMemory) {
                cachedHandle = prunedHandle
                cachedAead = prunedHandle.getPrimitive(RegistryConfiguration.get(), Aead::class.java)
            }
        }
    }

    override suspend fun resetAndRegenerate(reason: String): Long = mutex.withLock {
        check(tinkRegistered)
        val previousEpoch = cachedMetadata?.epoch ?: 0L
        wipeAllKeyFilesLocked()
        val nextEpoch = (previousEpoch + 1L).coerceAtLeast(1L)
        val created = initializeFreshWithPolicyLocked(initialEpoch = nextEpoch)
        created.meta.epoch
    }

    override suspend fun diagnostics(): SecurityDiagnostics = mutex.withLock {
        val state = obtainUnlockedStateLocked()
        SecurityDiagnostics(
            storeName = config.storeName,
            algorithm = config.algorithm,
            securityLevel = state.level,
            currentKeyEpoch = state.meta.epoch,
            keyCreatedAtEpochMs = state.meta.createdAtEpochMs,
            writesSinceRotation = state.meta.writesSinceRotation,
            hardwareBacked = state.level == SecurityLevel.STRONGBOX ||
                state.level == SecurityLevel.HARDWARE_TEE,
        )
    }

    private fun obtainUnlockedStateLocked(): UnlockedState {
        check(tinkRegistered)
        if (shouldCacheDekInMemory &&
            activeKekAead != null &&
            cachedHandle != null &&
            cachedAead != null &&
            cachedMetadata != null
        ) {
            return UnlockedState(
                kek = activeKekAead!!,
                handle = cachedHandle!!,
                aead = cachedAead!!,
                meta = cachedMetadata!!,
                level = currentSecurityLevel,
            )
        }
        enforceRestrictiveDirPermissions(storeDir)

        return if (keysetFile.exists()) {
            loadExistingWithPolicyLocked()
        } else {
            initializeFreshWithPolicyLocked(initialEpoch = 1L)
        }
    }

    private fun initializeFreshWithPolicyLocked(initialEpoch: Long): UnlockedState {
        try {
            val level = hardwareKekAead.ensureKeyAndGetSecurityLevel()
            return createFreshKeysetLocked(hardwareKekAead, level, initialEpoch)
        } catch (auth: UserAuthenticationRequiredException) {
            throw auth
        } catch (unavailable: KeystoreUnavailableException) {
            if (config.recoveryPolicy == KeystoreRecoveryPolicy.EXPLICIT_SOFTWARE_FALLBACK &&
                config.userAuthConfig == null
            ) {
                return activateSoftwareFallbackAndCreateLocked(
                    reason = unavailable.message ?: "android_keystore_unavailable",
                    initialEpoch = initialEpoch,
                )
            }
            throw unavailable
        }
    }

    private fun loadExistingWithPolicyLocked(): UnlockedState {
        // Software fallback is only allowed if explicitly enabled AND userAuthConfig is null.
        if (softwareSecretFile.exists()) {
            if (config.recoveryPolicy != KeystoreRecoveryPolicy.EXPLICIT_SOFTWARE_FALLBACK ||
                config.userAuthConfig != null
            ) {
                throw KeyManagementException(
                    "Store '${config.storeName}' was initialized with software fallback, which is disallowed by current policy '${config.recoveryPolicy}'."
                )
            }
            val swKek = obtainSoftwareFallbackKekLocked(createIfMissing = false)
            return loadKeysetWithKekLocked(swKek, SecurityLevel.SOFTWARE_FALLBACK)
        }

        return try {
            val level = hardwareKekAead.ensureKeyAndGetSecurityLevel()
            loadKeysetWithKekLocked(hardwareKekAead, level)
        } catch (auth: UserAuthenticationRequiredException) {
            throw auth
        } catch (unavailable: KeystoreUnavailableException) {
            // Note: Do NOT delete DataStore's .edst file here or wipe silently.
            // If EXPLICIT_SOFTWARE_FALLBACK is opted in without userAuthConfig AND the hardware
            // Keystore itself failed (no valid hardware keyset unwrap possible), allow fallback only
            // when AndroidKeyStore cannot operate; otherwise fail closed or let CLEAR_AND_REGENERATE
            // handle it once via EncryptedOkioSerializer.
            if (config.recoveryPolicy == KeystoreRecoveryPolicy.EXPLICIT_SOFTWARE_FALLBACK &&
                config.userAuthConfig == null
            ) {
                throw KeystoreUnavailableException(
                    "Hardware Keystore failed for existing store '${config.storeName}'. " +
                        "Use CLEAR_AND_REGENERATE to reset or resolve Keystore lock.",
                    unavailable,
                )
            }
            throw unavailable
        }
    }

    private fun activateSoftwareFallbackAndCreateLocked(reason: String, initialEpoch: Long): UnlockedState {
        check(config.userAuthConfig == null) {
            "Software fallback cannot be activated when userAuthConfig is enabled"
        }
        val swKek = obtainSoftwareFallbackKekLocked(createIfMissing = true)
        val state = createFreshKeysetLocked(swKek, SecurityLevel.SOFTWARE_FALLBACK, initialEpoch)
        config.eventListener?.onEvent(
            SecurityEvent.SoftwareFallbackActivated(
                storeName = config.storeName,
                reason = reason,
            )
        )
        return state
    }

    private fun createFreshKeysetLocked(
        kek: Aead,
        level: SecurityLevel,
        initialEpoch: Long,
    ): UnlockedState {
        val handle = KeysetHandle.generateNew(KeyTemplates.get(tinkParameterName(config.algorithm)))
        val aead = handle.getPrimitive(RegistryConfiguration.get(), Aead::class.java)
        val meta = AndroidKeyRotationMetadata(
            epoch = initialEpoch,
            createdAtEpochMs = System.currentTimeMillis(),
            writesSinceRotation = 0L,
        )
        persistKeysetLocked(kek, handle)
        persistMetadataLocked(aead, meta)
        cachedMetadata = meta
        currentSecurityLevel = level
        if (shouldCacheDekInMemory) {
            activeKekAead = kek
            cachedHandle = handle
            cachedAead = aead
        }
        config.eventListener?.onEvent(
            SecurityEvent.KeyInitialized(
                storeName = config.storeName,
                securityLevel = level,
                epoch = initialEpoch,
            )
        )
        return UnlockedState(kek, handle, aead, meta, level)
    }

    private fun loadKeysetWithKekLocked(kek: Aead, level: SecurityLevel): UnlockedState {
        val encryptedBytes = keysetFile.readBytes()
        val handle = try {
            TinkProtoKeysetFormat.parseEncryptedKeyset(
                encryptedBytes,
                kek,
                keysetAssociatedData(),
            )
        } catch (t: Throwable) {
            if (t is SecurityStorageException) throw t
            throw StoreTamperedOrCorruptedException(
                "Failed to unwrap Tink keyset for '${config.storeName}'",
                t,
            )
        }
        val aead = handle.getPrimitive(RegistryConfiguration.get(), Aead::class.java)
        val meta = if (metadataFile.exists()) {
            loadMetadataLocked(aead)
        } else {
            AndroidKeyRotationMetadata(
                epoch = 1L,
                createdAtEpochMs = System.currentTimeMillis(),
                writesSinceRotation = 0L,
            ).also { persistMetadataLocked(aead, it) }
        }
        cachedMetadata = meta
        currentSecurityLevel = level
        if (shouldCacheDekInMemory) {
            activeKekAead = kek
            cachedHandle = handle
            cachedAead = aead
        }
        return UnlockedState(kek, handle, aead, meta, level)
    }

    private fun rotateKeyLocked(state: UnlockedState, maxRetainedKeys: Int, trigger: String): Long {
        val builder = KeysetHandle.newBuilder(state.handle)
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
        val newEpoch = state.meta.epoch + 1L
        val newMeta = AndroidKeyRotationMetadata(
            epoch = newEpoch,
            createdAtEpochMs = System.currentTimeMillis(),
            writesSinceRotation = 0L,
        )
        persistKeysetLocked(state.kek, provisional)
        persistMetadataLocked(newAead, newMeta)
        cachedMetadata = newMeta
        if (shouldCacheDekInMemory) {
            cachedHandle = provisional
            cachedAead = newAead
        }
        config.eventListener?.onEvent(
            SecurityEvent.KeyRotated(
                storeName = config.storeName,
                oldEpoch = state.meta.epoch,
                newEpoch = newEpoch,
                trigger = trigger,
            )
        )
        return newEpoch
    }

    private fun wipeAllKeyFilesLocked() {
        runCatching { hardwareKekAead.deleteMasterKey() }
        keysetFile.delete()
        metadataFile.delete()
        softwareSecretFile.delete()
        activeKekAead = null
        cachedHandle = null
        cachedAead = null
        cachedMetadata = null
        currentSecurityLevel = SecurityLevel.UNKNOWN
    }

    private fun obtainSoftwareFallbackKekLocked(createIfMissing: Boolean): Aead {
        val secret = if (softwareSecretFile.exists()) {
            softwareSecretFile.readBytes()
        } else {
            if (!createIfMissing) {
                throw KeyManagementException("Missing software fallback secret for '${config.storeName}'")
            }
            ByteArray(SOFTWARE_SECRET_BYTES).also {
                secureRandom.nextBytes(it)
                atomicWriteFile(softwareSecretFile, it)
            }
        }
        val info = "${context.applicationContext.packageName}:${config.storeName}".encodeToByteArray()
        val derivedKey = Hkdf.computeHkdf("HMACSHA256", secret, null, info, 32)
        secret.wipe()
        return try {
            AesGcmJce(derivedKey)
        } finally {
            derivedKey.wipe()
        }
    }

    private fun persistKeysetLocked(kek: Aead, handle: KeysetHandle) {
        val serialized = TinkProtoKeysetFormat.serializeEncryptedKeyset(
            handle,
            kek,
            keysetAssociatedData(),
        )
        try {
            atomicWriteFile(keysetFile, serialized)
        } finally {
            serialized.wipe()
        }
    }

    private fun persistMetadataLocked(aead: Aead, meta: AndroidKeyRotationMetadata) {
        val plain = json.encodeToString(AndroidKeyRotationMetadata.serializer(), meta).encodeToByteArray()
        try {
            val encrypted = aead.encrypt(plain, metadataAssociatedData())
            atomicWriteFile(metadataFile, encrypted)
        } finally {
            plain.wipe()
        }
    }

    private fun loadMetadataLocked(aead: Aead): AndroidKeyRotationMetadata {
        val encrypted = metadataFile.readBytes()
        val plain = try {
            aead.decrypt(encrypted, metadataAssociatedData())
        } catch (e: GeneralSecurityException) {
            throw StoreTamperedOrCorruptedException(
                "Key rotation metadata authentication failed for '${config.storeName}'",
                e,
            )
        }
        return try {
            json.decodeFromString(AndroidKeyRotationMetadata.serializer(), plain.decodeToString())
        } finally {
            plain.wipe()
        }
    }

    private fun atomicWriteFile(target: File, bytes: ByteArray) {
        val tmp = File(target.parentFile, "${target.name}.tmp")
        val tmpPath = tmp.toPath()
        val targetPath = target.toPath()
        if (tmp.exists()) {
            tmp.delete()
        }
        try {
            val perms = PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))
            Files.createFile(tmpPath, perms)
        } catch (_: UnsupportedOperationException) {
            tmp.createNewFile()
            enforceFilePermissions(tmp)
        }
        FileOutputStream(tmp).use { fos ->
            fos.write(bytes)
            fos.flush()
            fos.fd.sync()
        }
        try {
            Files.move(tmpPath, targetPath, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
        } catch (_: AtomicMoveNotSupportedException) {
            Files.move(tmpPath, targetPath, StandardCopyOption.REPLACE_EXISTING)
        }
        enforceFilePermissions(target)
        runCatching {
            target.parentFile?.toPath()?.let { dirPath ->
                FileChannel.open(dirPath, StandardOpenOption.READ).use { it.force(true) }
            }
        }
    }

    private fun enforceFilePermissions(file: File) {
        file.setReadable(false, false)
        file.setReadable(true, true)
        file.setWritable(false, false)
        file.setWritable(true, true)
        file.setExecutable(false, false)
    }

    private fun keysetAssociatedData(): ByteArray =
        buildDomainAad(KEYSET_AAD_TAG, "${context.applicationContext.packageName}:${config.storeName}")

    private fun metadataAssociatedData(): ByteArray =
        buildDomainAad(METADATA_AAD_TAG, "${context.applicationContext.packageName}:${config.storeName}")

    private fun buildDomainAad(domain: ByteArray, scope: String): ByteArray {
        val scopeBytes = scope.encodeToByteArray()
        return Buffer().apply {
            writeInt(domain.size)
            write(domain)
            writeInt(scopeBytes.size)
            write(scopeBytes)
        }.readByteArray()
    }

    private fun tinkParameterName(algorithm: CipherAlgorithm): String = when (algorithm) {
        CipherAlgorithm.AES256_GCM -> "AES256_GCM"
        CipherAlgorithm.XCHACHA20_POLY1305 -> "XCHACHA20_POLY1305"
    }
}
