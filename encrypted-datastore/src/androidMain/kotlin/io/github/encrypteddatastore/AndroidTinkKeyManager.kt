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
    private val storeDataFile = File(storeDir, "${config.storeName}.edst")
    private val softwareSecretFile = File(storeDir, "${config.storeName}.swkek")

    private val hardwareKekAead = AndroidKeyStoreAead(context.applicationContext, config)

    private var activeKekAead: Aead? = null
    private var cachedHandle: KeysetHandle? = null
    private var cachedAead: Aead? = null
    private var cachedMetadata: AndroidKeyRotationMetadata? = null
    private var currentSecurityLevel: SecurityLevel = SecurityLevel.HARDWARE_TEE

    override val securityLevel: SecurityLevel
        get() = currentSecurityLevel

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
                if (currentHandle.getAt(i).id != primaryId) {
                    builder.deleteAt(i)
                }
            }
            val prunedHandle = builder.build()
            persistKeysetLocked(activeKekAead!!, prunedHandle)
            cachedHandle = prunedHandle
            cachedAead = prunedHandle.getPrimitive(RegistryConfiguration.get(), Aead::class.java)
        }
    }

    override suspend fun resetAndRegenerate(reason: String): Long = mutex.withLock {
        check(tinkRegistered)
        val previousEpoch = cachedMetadata?.epoch ?: 0L
        wipeAllKeyFilesLocked()
        val nextEpoch = (previousEpoch + 1L).coerceAtLeast(1L)
        initializeFreshWithPolicyLocked(initialEpoch = nextEpoch)
        nextEpoch
    }

    override suspend fun diagnostics(): SecurityDiagnostics = mutex.withLock {
        ensureInitializedLocked()
        val meta = cachedMetadata!!
        SecurityDiagnostics(
            storeName = config.storeName,
            algorithm = config.algorithm,
            securityLevel = currentSecurityLevel,
            currentKeyEpoch = meta.epoch,
            keyCreatedAtEpochMs = meta.createdAtEpochMs,
            writesSinceRotation = meta.writesSinceRotation,
            hardwareBacked = currentSecurityLevel == SecurityLevel.STRONGBOX ||
                currentSecurityLevel == SecurityLevel.HARDWARE_TEE,
        )
    }

    private suspend fun ensureInitializedLocked() {
        check(tinkRegistered)
        if (cachedHandle != null && cachedAead != null && cachedMetadata != null) return
        enforceRestrictiveDirPermissions(storeDir)

        if (keysetFile.exists()) {
            loadExistingWithPolicyLocked()
        } else {
            initializeFreshWithPolicyLocked(initialEpoch = 1L)
        }
    }

    private suspend fun initializeFreshWithPolicyLocked(initialEpoch: Long) {
        try {
            val level = hardwareKekAead.ensureKeyAndGetSecurityLevel()
            val kek = hardwareKekAead
            createFreshKeysetLocked(kek, level, initialEpoch)
        } catch (auth: UserAuthenticationRequiredException) {
            throw auth
        } catch (e: SecurityStorageException) {
            if (config.recoveryPolicy == KeystoreRecoveryPolicy.EXPLICIT_SOFTWARE_FALLBACK) {
                activateSoftwareFallbackAndCreateLocked(
                    reason = e.message ?: "android_keystore_unavailable",
                    initialEpoch = initialEpoch,
                )
            } else {
                throw e
            }
        }
    }

    private suspend fun loadExistingWithPolicyLocked() {
        // If explicit software fallback was previously activated for this store, use software KEK directly.
        if (softwareSecretFile.exists() && config.recoveryPolicy == KeystoreRecoveryPolicy.EXPLICIT_SOFTWARE_FALLBACK) {
            val swKek = obtainSoftwareFallbackKekLocked(createIfMissing = false)
            try {
                loadKeysetWithKekLocked(swKek, SecurityLevel.SOFTWARE_FALLBACK)
                return
            } catch (e: SecurityStorageException) {
                // Corrupted software keyset: wipe and regenerate cleanly under explicit fallback.
                wipeAllKeyFilesLocked()
                activateSoftwareFallbackAndCreateLocked(
                    reason = e.message ?: "corrupted_software_keyset",
                    initialEpoch = 1L,
                )
                return
            }
        }

        try {
            val level = hardwareKekAead.ensureKeyAndGetSecurityLevel()
            loadKeysetWithKekLocked(hardwareKekAead, level)
        } catch (auth: UserAuthenticationRequiredException) {
            // Never wipe or downgrade when user simply needs to unlock / authenticate.
            throw auth
        } catch (e: SecurityStorageException) {
            when (config.recoveryPolicy) {
                KeystoreRecoveryPolicy.STRICT -> throw e
                KeystoreRecoveryPolicy.CLEAR_AND_REGENERATE -> {
                    val reason = e.message ?: e::class.simpleName ?: "keystore_failure"
                    wipeAllKeyFilesLocked()
                    storeDataFile.delete()
                    val level = hardwareKekAead.ensureKeyAndGetSecurityLevel()
                    createFreshKeysetLocked(hardwareKekAead, level, initialEpoch = 1L)
                    config.eventListener?.onEvent(
                        SecurityEvent.CorruptionRecovered(
                            storeName = config.storeName,
                            reason = reason,
                            newEpoch = 1L,
                        )
                    )
                    config.onRecovery?.invoke(
                        RecoveryEvent(
                            storeName = config.storeName,
                            reason = reason,
                            newEpoch = 1L,
                        )
                    )
                }

                KeystoreRecoveryPolicy.EXPLICIT_SOFTWARE_FALLBACK -> {
                    val reason = e.message ?: e::class.simpleName ?: "oem_keystore_broken"
                    wipeAllKeyFilesLocked()
                    storeDataFile.delete()
                    activateSoftwareFallbackAndCreateLocked(reason = reason, initialEpoch = 1L)
                    config.onRecovery?.invoke(
                        RecoveryEvent(
                            storeName = config.storeName,
                            reason = reason,
                            newEpoch = 1L,
                        )
                    )
                }
            }
        }
    }

    private fun activateSoftwareFallbackAndCreateLocked(reason: String, initialEpoch: Long) {
        val swKek = obtainSoftwareFallbackKekLocked(createIfMissing = true)
        createFreshKeysetLocked(swKek, SecurityLevel.SOFTWARE_FALLBACK, initialEpoch)
        config.eventListener?.onEvent(
            SecurityEvent.SoftwareFallbackActivated(
                storeName = config.storeName,
                reason = reason,
            )
        )
    }

    private fun createFreshKeysetLocked(kek: Aead, level: SecurityLevel, initialEpoch: Long) {
        val handle = KeysetHandle.generateNew(KeyTemplates.get(tinkParameterName(config.algorithm)))
        val aead = handle.getPrimitive(RegistryConfiguration.get(), Aead::class.java)
        val meta = AndroidKeyRotationMetadata(
            epoch = initialEpoch,
            createdAtEpochMs = System.currentTimeMillis(),
            writesSinceRotation = 0L,
        )
        persistKeysetLocked(kek, handle)
        persistMetadataLocked(aead, meta)
        activeKekAead = kek
        cachedHandle = handle
        cachedAead = aead
        cachedMetadata = meta
        currentSecurityLevel = level
        config.eventListener?.onEvent(
            SecurityEvent.KeyInitialized(
                storeName = config.storeName,
                securityLevel = level,
                epoch = initialEpoch,
            )
        )
    }

    private fun loadKeysetWithKekLocked(kek: Aead, level: SecurityLevel) {
        val encryptedBytes = keysetFile.readBytes()
        val handle = try {
            TinkProtoKeysetFormat.parseEncryptedKeyset(
                encryptedBytes,
                kek,
                keysetAssociatedData(),
            )
        } catch (t: Throwable) {
            if (t is SecurityStorageException) throw t
            throw KeyManagementException("Failed to unwrap Tink keyset for '${config.storeName}'", t)
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
        activeKekAead = kek
        cachedHandle = handle
        cachedAead = aead
        cachedMetadata = meta
        currentSecurityLevel = level
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
        val newMeta = AndroidKeyRotationMetadata(
            epoch = newEpoch,
            createdAtEpochMs = System.currentTimeMillis(),
            writesSinceRotation = 0L,
        )
        persistKeysetLocked(activeKekAead!!, provisional)
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

    private suspend fun wipeAllKeyFilesLocked() {
        runCatching { hardwareKekAead.deleteMasterKey() }
        keysetFile.delete()
        metadataFile.delete()
        softwareSecretFile.delete()
        activeKekAead = null
        cachedHandle = null
        cachedAead = null
        cachedMetadata = null
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
        FileOutputStream(tmp).use { fos ->
            fos.write(bytes)
            fos.flush()
            fos.fd.sync()
        }
        enforceFilePermissions(tmp)
        if (!tmp.renameTo(target)) {
            if (target.exists()) target.delete()
            check(tmp.renameTo(target)) { "Failed to atomically move ${tmp.name} to ${target.name}" }
        }
        enforceFilePermissions(target)
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
