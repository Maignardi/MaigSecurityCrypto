package io.github.encrypteddatastore

import android.system.Os
import android.system.OsConstants
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
 * stored in `noBackupFilesDir` with API 23+-compatible atomic writes (`android.system.Os`),
 * 0600 permissions, key rotation, and explicit OEM Keystore failure policies.
 *
 * When [SecurityConfig.userAuthConfig] is configured, the DEK keyset is NOT cached in RAM
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
        private const val META_CHECKPOINT_INTERVAL = 10L
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
    private var inMemoryWritesSinceRotation: Long? = null

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
        val state = obtainUnlockedStateLocked()
        inMemoryWritesSinceRotation ?: state.meta.writesSinceRotation
    }

    override suspend fun encryptEnvelope(
        plaintext: ByteArray,
        rotationPolicy: KeyRotationPolicy,
        headerBuilder: (CipherAlgorithm, Long) -> ByteArray,
        aadBuilder: (ByteArray) -> ByteArray,
    ): EncryptedEnvelopeResult = mutex.withLock {
        var state = obtainUnlockedStateLocked()
        state = rotateIfPolicyRequiresLocked(state, rotationPolicy)
        val header = headerBuilder(config.algorithm, state.meta.epoch)
        val aad = aadBuilder(header)
        val ciphertext = try {
            state.aead.encrypt(plaintext, aad)
        } catch (e: GeneralSecurityException) {
            throw EncryptionException("AEAD encryption failed for '${config.storeName}'", e)
        }
        val nextWrites = (inMemoryWritesSinceRotation ?: state.meta.writesSinceRotation) + 1L
        val updatedMeta = state.meta.copy(writesSinceRotation = nextWrites)
        if (shouldPersistMetadataWrite(rotationPolicy, nextWrites)) {
            persistMetadataLocked(state.aead, updatedMeta)
        }
        inMemoryWritesSinceRotation = nextWrites
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

    override suspend fun rotateKey(maxRetainedKeys: Int, trigger: String): Long = mutex.withLock {
        val state = obtainUnlockedStateLocked()
        rotateKeyLocked(state, maxRetainedKeys.coerceAtLeast(2), trigger).meta.epoch
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
        val nextEpoch = (previousEpoch + 1L).coerceAtLeast(1L)

        // Generate fresh keyset & KEK before wiping old files unless deletion is required for alias recreation.
        wipeAllKeyFilesLocked()
        val created = initializeFreshWithPolicyLocked(initialEpoch = nextEpoch)
        created.meta.epoch
    }

    override suspend fun diagnostics(): SecurityDiagnostics = mutex.withLock {
        val state = obtainUnlockedStateLocked()
        val writes = inMemoryWritesSinceRotation ?: state.meta.writesSinceRotation
        SecurityDiagnostics(
            storeName = config.storeName,
            algorithm = config.algorithm,
            securityLevel = state.level,
            currentKeyEpoch = state.meta.epoch,
            keyCreatedAtEpochMs = state.meta.createdAtEpochMs,
            writesSinceRotation = writes,
            hardwareBacked = state.level == SecurityLevel.STRONGBOX ||
                state.level == SecurityLevel.HARDWARE_TEE,
        )
    }

    private fun shouldPersistMetadataWrite(policy: KeyRotationPolicy, writes: Long): Boolean {
        if (policy !is KeyRotationPolicy.Automatic) return false
        return policy.maxWritesBeforeRotation < META_CHECKPOINT_INTERVAL * 2 ||
            writes % META_CHECKPOINT_INTERVAL == 0L
    }

    private fun rotateIfPolicyRequiresLocked(
        state: UnlockedState,
        policy: KeyRotationPolicy,
    ): UnlockedState {
        if (policy !is KeyRotationPolicy.Automatic) return state
        val nowMs = System.currentTimeMillis()
        val ageMs = (nowMs - state.meta.createdAtEpochMs).coerceAtLeast(0L)
        val maxAgeMs = policy.maxKeyAge.toLong(DurationUnit.MILLISECONDS)
        val writes = inMemoryWritesSinceRotation ?: state.meta.writesSinceRotation
        val trigger = when {
            writes >= policy.maxWritesBeforeRotation -> "write_limit"
            ageMs >= maxAgeMs -> "max_age"
            else -> null
        }
        return if (trigger != null) {
            rotateKeyLocked(state, policy.maxRetainedKeys.coerceAtLeast(2), trigger)
        } else {
            state
        }
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

        val level = hardwareKekAead.ensureKeyAndGetSecurityLevel()
        return loadKeysetWithKekLocked(hardwareKekAead, level)
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
        inMemoryWritesSinceRotation = 0L
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
        val syncedWrites = inMemoryWritesSinceRotation ?: meta.writesSinceRotation
        val syncedMeta = meta.copy(writesSinceRotation = syncedWrites)
        cachedMetadata = syncedMeta
        inMemoryWritesSinceRotation = syncedWrites
        currentSecurityLevel = level
        if (shouldCacheDekInMemory) {
            activeKekAead = kek
            cachedHandle = handle
            cachedAead = aead
        }
        return UnlockedState(kek, handle, aead, syncedMeta, level)
    }

    private fun rotateKeyLocked(
        state: UnlockedState,
        maxRetainedKeys: Int,
        trigger: String,
    ): UnlockedState {
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
        inMemoryWritesSinceRotation = 0L
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
        return UnlockedState(state.kek, provisional, newAead, newMeta, state.level)
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
        inMemoryWritesSinceRotation = null
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

    /**
     * API 23+-compatible atomic file write using `android.system.Os` (`open`/`chmod`/`rename`/`fsync`)
     * with safe fallback for host Robolectric environments. Never uses `java.nio.file.*` (API 26+).
     */
    private fun atomicWriteFile(target: File, bytes: ByteArray) {
        val tmp = File(target.parentFile, "${target.name}.tmp")
        if (tmp.exists()) {
            tmp.delete()
        }

        val createdWithOs = runCatching {
            val fd = Os.open(
                tmp.absolutePath,
                OsConstants.O_CREAT or OsConstants.O_WRONLY or OsConstants.O_TRUNC,
                0b110_000_000, // 0600 before writing any bytes
            )
            Os.close(fd)
            true
        }.getOrDefault(false)

        if (!createdWithOs) {
            tmp.createNewFile()
            enforceFilePermissions(tmp)
        }

        FileOutputStream(tmp).use { fos ->
            fos.write(bytes)
            fos.flush()
            fos.fd.sync()
        }

        val renamedWithOs = runCatching {
            Os.rename(tmp.absolutePath, target.absolutePath)
            true
        }.getOrDefault(false)

        if (!renamedWithOs) {
            check(tmp.renameTo(target)) {
                "Failed to atomically move ${tmp.name} to ${target.name}"
            }
        }
        enforceFilePermissions(target)

        // Best-effort directory fsync (API 21+ Os.open on directory)
        runCatching {
            target.parentFile?.let { dir ->
                val dirFd = Os.open(dir.absolutePath, OsConstants.O_RDONLY, 0)
                try {
                    Os.fsync(dirFd)
                } finally {
                    Os.close(dirFd)
                }
            }
        }
    }

    private fun enforceFilePermissions(file: File) {
        runCatching { Os.chmod(file.absolutePath, 0b110_000_000) }
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
        CipherAlgorithm.AES256_CTR_HMAC_SHA256 -> "AES256_CTR_HMAC_SHA256"
    }
}
