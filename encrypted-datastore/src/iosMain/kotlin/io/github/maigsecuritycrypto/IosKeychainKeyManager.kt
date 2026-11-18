@file:OptIn(
    kotlinx.cinterop.ExperimentalForeignApi::class,
    kotlinx.cinterop.BetaInteropApi::class,
    kotlin.io.encoding.ExperimentalEncodingApi::class,
    dev.whyoleg.cryptography.DelicateCryptographyApi::class,
)

package io.github.maigsecuritycrypto

import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.AES
import dev.whyoleg.cryptography.algorithms.HMAC
import dev.whyoleg.cryptography.algorithms.SHA256
import kotlinx.cinterop.COpaquePointer
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.usePinned
import kotlinx.cinterop.value
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import okio.Buffer
import platform.CoreFoundation.CFDictionaryAddValue
import platform.CoreFoundation.CFDictionaryCreateMutable
import platform.CoreFoundation.CFDictionaryRef
import platform.CoreFoundation.CFErrorRefVar
import platform.CoreFoundation.CFRelease
import platform.CoreFoundation.CFTypeRef
import platform.CoreFoundation.CFTypeRefVar
import platform.CoreFoundation.kCFBooleanTrue
import platform.CoreFoundation.kCFTypeDictionaryKeyCallBacks
import platform.CoreFoundation.kCFTypeDictionaryValueCallBacks
import platform.Foundation.CFBridgingRelease
import platform.Foundation.CFBridgingRetain
import platform.Foundation.NSData
import platform.Foundation.NSDate
import platform.Foundation.create
import platform.Foundation.timeIntervalSince1970
import platform.LocalAuthentication.LAContext
import platform.Security.SecAccessControlCreateWithFlags
import platform.Security.SecItemAdd
import platform.Security.SecItemCopyMatching
import platform.Security.SecItemDelete
import platform.Security.SecItemUpdate
import platform.Security.SecRandomCopyBytes
import platform.Security.errSecAuthFailed
import platform.Security.errSecDuplicateItem
import platform.Security.errSecInteractionNotAllowed
import platform.Security.errSecItemNotFound
import platform.Security.errSecSuccess
import platform.Security.errSecUserCanceled
import platform.Security.kSecAccessControlBiometryAny
import platform.Security.kSecAccessControlBiometryCurrentSet
import platform.Security.kSecAccessControlUserPresence
import platform.Security.kSecAttrAccessControl
import platform.Security.kSecAttrAccessible
import platform.Security.kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
import platform.Security.kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
import platform.Security.kSecAttrAccessibleWhenUnlockedThisDeviceOnly
import platform.Security.kSecAttrAccount
import platform.Security.kSecAttrService
import platform.Security.kSecClass
import platform.Security.kSecClassGenericPassword
import platform.Security.kSecMatchLimit
import platform.Security.kSecMatchLimitOne
import platform.Security.kSecRandomDefault
import platform.Security.kSecReturnData
import platform.Security.kSecUseAuthenticationContext
import platform.Security.kSecValueData
import platform.posix.memcpy
import kotlin.io.encoding.Base64
import kotlin.time.DurationUnit

@Serializable
internal data class IosKeychainKeysetRecord(
    val currentEpoch: Long,
    val keyCreatedAtEpochMs: Long,
    val writesSinceRotation: Long,
    val epochKeysBase64: Map<Long, String>,
)

/**
 * Encrypt-then-MAC AEAD built on Apple `CommonCrypto` (`AES-256-CTR` + `HMAC-SHA256`)
 * with domain-separated subkeys and length-prefixed AAD.
 */
internal object IosAesCtrHmacCipher {
    const val IV_BYTES = 16
    const val MAC_TAG_BYTES = 32
    private val ENC_SUBKEY_LABEL = "EDST_IOS_CTR_ENC_V1".encodeToByteArray()
    private val MAC_SUBKEY_LABEL = "EDST_IOS_HMAC_SHA256_V1".encodeToByteArray()

    private val provider = CryptographyProvider.Default
    private val aesCtr = provider.get(AES.CTR)
    private val hmac = provider.get(HMAC)

    suspend fun encrypt(
        masterKey: ByteArray,
        plaintext: ByteArray,
        associatedData: ByteArray,
        iv: ByteArray,
    ): ByteArray {
        require(iv.size == IV_BYTES) { "IV must be $IV_BYTES bytes" }
        var encKeyBytes: ByteArray? = null
        var macKeyBytes: ByteArray? = null
        try {
            val (derivedEnc, derivedMac) = deriveSubkeys(masterKey)
            encKeyBytes = derivedEnc
            macKeyBytes = derivedMac

            val aesKey = aesCtr.keyDecoder().decodeFromByteArray(AES.Key.Format.RAW, derivedEnc)
            val ct = aesKey.cipher().encryptWithIv(iv, plaintext)

            val macInput = buildMacInput(associatedData, iv, ct)
            val macKey = hmac.keyDecoder(SHA256).decodeFromByteArray(HMAC.Key.Format.RAW, derivedMac)
            val tag = macKey.signatureGenerator().generateSignature(macInput)

            val payload = ByteArray(IV_BYTES + ct.size + tag.size)
            iv.copyInto(payload, destinationOffset = 0)
            ct.copyInto(payload, destinationOffset = IV_BYTES)
            tag.copyInto(payload, destinationOffset = IV_BYTES + ct.size)
            return payload
        } finally {
            encKeyBytes?.wipe()
            macKeyBytes?.wipe()
        }
    }

    suspend fun decrypt(
        masterKey: ByteArray,
        ciphertext: ByteArray,
        associatedData: ByteArray,
        storeName: String,
        keyEpoch: Long,
    ): ByteArray {
        if (ciphertext.size < IV_BYTES + MAC_TAG_BYTES) {
            throw MaigStoreTamperedOrCorruptedException(
                "iOS encrypted payload is truncated (${ciphertext.size} bytes)"
            )
        }
        var encKeyBytes: ByteArray? = null
        var macKeyBytes: ByteArray? = null
        try {
            val (derivedEnc, derivedMac) = deriveSubkeys(masterKey)
            encKeyBytes = derivedEnc
            macKeyBytes = derivedMac

            val iv = ciphertext.copyOfRange(0, IV_BYTES)
            val ctEnd = ciphertext.size - MAC_TAG_BYTES
            val ct = ciphertext.copyOfRange(IV_BYTES, ctEnd)
            val tag = ciphertext.copyOfRange(ctEnd, ciphertext.size)

            val macInput = buildMacInput(associatedData, iv, ct)
            val macKey = hmac.keyDecoder(SHA256).decodeFromByteArray(HMAC.Key.Format.RAW, derivedMac)
            val validTag = macKey.signatureVerifier().tryVerifySignature(macInput, tag)
            if (!validTag) {
                throw MaigStoreTamperedOrCorruptedException(
                    "iOS HMAC authentication failed for '$storeName' (epoch=$keyEpoch)"
                )
            }

            val aesKey = aesCtr.keyDecoder().decodeFromByteArray(AES.Key.Format.RAW, derivedEnc)
            return aesKey.cipher().decryptWithIv(iv, ct)
        } finally {
            encKeyBytes?.wipe()
            macKeyBytes?.wipe()
        }
    }

    private suspend fun deriveSubkeys(masterKey: ByteArray): Pair<ByteArray, ByteArray> {
        val prfKey = hmac.keyDecoder(SHA256).decodeFromByteArray(HMAC.Key.Format.RAW, masterKey)
        val generator = prfKey.signatureGenerator()
        val encKey = generator.generateSignature(ENC_SUBKEY_LABEL)
        val macKey = generator.generateSignature(MAC_SUBKEY_LABEL)
        return encKey to macKey
    }

    private fun buildMacInput(aad: ByteArray, iv: ByteArray, ct: ByteArray): ByteArray {
        return Buffer().apply {
            writeInt(aad.size)
            write(aad)
            write(iv)
            write(ct)
        }.readByteArray()
    }
}

/**
 * iOS Keychain-backed [KeyManager] using Apple native `CommonCrypto` via [IosAesCtrHmacCipher]
 * and `ThisDeviceOnly` Keychain items (`SecItem*`).
 *
 * - Only [MaigCipherAlgorithm.AES256_CTR_HMAC_SHA256] is supported on iOS.
 * - When [MaigSecurityConfig.userAuthConfig] is set, Keychain items use `SecAccessControl` and an
 *   expiring `LAContext` that is invalidated after `authValidityDurationSeconds`.
 */
internal class IosKeychainKeyManager(
    private val context: MaigStorageContext,
    private val config: MaigSecurityConfig,
) : KeyManager {

    private companion object {
        const val KEY_BYTES = 32
        const val META_CHECKPOINT_INTERVAL = 10L
        const val MAX_APPLE_TOUCH_ID_REUSE_SECONDS = 300
    }

    init {
        if (config.algorithm != MaigCipherAlgorithm.AES256_CTR_HMAC_SHA256) {
            throw MaigKeyManagementException(
                "MaigCipherAlgorithm.${config.algorithm} is not supported on iOS; " +
                    "use MaigCipherAlgorithm.AES256_CTR_HMAC_SHA256 (the iOS default)."
            )
        }
    }

    private val mutex = Mutex()
    private val json = Json { ignoreUnknownKeys = true }
    private val serviceName = context.resolvedServiceName()
    private val accountName = "edst_dek_${config.storeName}"
    private val shouldCacheInMemory: Boolean = config.userAuthConfig == null

    private var currentLaContext: LAContext? = null
    private var laContextCreatedAtMs: Long = 0L

    private var cachedRecord: IosKeychainKeysetRecord? = null
    private var inMemoryWritesSinceRotation: Long? = null
    private var lastKnownEpoch: Long = 0L

    override suspend fun currentEpoch(): Long = mutex.withLock {
        ensureInitializedLocked().currentEpoch
    }

    override suspend fun keyCreatedAtEpochMs(): Long = mutex.withLock {
        ensureInitializedLocked().keyCreatedAtEpochMs
    }

    override suspend fun writesSinceRotation(): Long = mutex.withLock {
        val record = ensureInitializedLocked()
        inMemoryWritesSinceRotation ?: record.writesSinceRotation
    }

    override suspend fun encryptEnvelope(
        plaintext: ByteArray,
        rotationPolicy: MaigKeyRotationPolicy,
        headerBuilder: (MaigCipherAlgorithm, Long) -> ByteArray,
        aadBuilder: (ByteArray) -> ByteArray,
    ): EncryptedEnvelopeResult = mutex.withLock {
        var record = ensureInitializedLocked()
        record = rotateIfPolicyRequiresLocked(record, rotationPolicy)
        val keyBase64 = record.epochKeysBase64[record.currentEpoch]
            ?: throw MaigKeyManagementException("Missing DEK for epoch ${record.currentEpoch}")
        val masterKey = Base64.decode(keyBase64)
        try {
            val header = headerBuilder(MaigCipherAlgorithm.AES256_CTR_HMAC_SHA256, record.currentEpoch)
            val aad = aadBuilder(header)
            val iv = generateRandomBytes(IosAesCtrHmacCipher.IV_BYTES)
            val payload = IosAesCtrHmacCipher.encrypt(masterKey, plaintext, aad, iv)

            val nextWrites = (inMemoryWritesSinceRotation ?: record.writesSinceRotation) + 1L
            val updated = record.copy(writesSinceRotation = nextWrites)
            if (shouldPersistMetadataWrite(rotationPolicy, nextWrites)) {
                saveRecordToKeychain(updated)
            }
            inMemoryWritesSinceRotation = nextWrites
            lastKnownEpoch = record.currentEpoch
            if (shouldCacheInMemory) {
                cachedRecord = updated
            }
            EncryptedEnvelopeResult(
                keyEpoch = record.currentEpoch,
                envelopeBytes = EncryptedEnvelopeCodec.encode(header, payload),
            )
        } catch (e: MaigSecurityStorageException) {
            throw e
        } catch (e: Throwable) {
            throw MaigEncryptionException("iOS AEAD encryption failed for '${config.storeName}'", e)
        } finally {
            masterKey.wipe()
        }
    }

    override suspend fun decrypt(
        ciphertext: ByteArray,
        algorithm: MaigCipherAlgorithm,
        keyEpoch: Long,
        associatedData: ByteArray,
    ): ByteArray = mutex.withLock {
        if (algorithm != MaigCipherAlgorithm.AES256_CTR_HMAC_SHA256) {
            throw MaigStoreTamperedOrCorruptedException(
                "Unsupported cipher algorithm $algorithm on iOS for '${config.storeName}'"
            )
        }
        val record = ensureInitializedLocked()
        val keyBase64 = record.epochKeysBase64[keyEpoch]
            ?: throw MaigStoreTamperedOrCorruptedException(
                "No retained DEK for epoch $keyEpoch in '${config.storeName}'"
            )
        val masterKey = Base64.decode(keyBase64)
        try {
            IosAesCtrHmacCipher.decrypt(
                masterKey = masterKey,
                ciphertext = ciphertext,
                associatedData = associatedData,
                storeName = config.storeName,
                keyEpoch = keyEpoch,
            )
        } catch (e: MaigSecurityStorageException) {
            throw e
        } catch (e: Throwable) {
            throw MaigStoreTamperedOrCorruptedException(
                "iOS decryption failed for '${config.storeName}' (epoch=$keyEpoch)",
                e,
            )
        } finally {
            masterKey.wipe()
        }
    }

    override suspend fun rotateKey(maxRetainedKeys: Int, trigger: String): Long = mutex.withLock {
        val record = ensureInitializedLocked()
        rotateKeyLocked(record, maxRetainedKeys.coerceAtLeast(2), trigger).currentEpoch
    }

    override suspend fun pruneHistoricalKeys() {
        mutex.withLock {
            val record = ensureInitializedLocked()
            val currentKey = record.epochKeysBase64[record.currentEpoch]
                ?: throw MaigKeyManagementException("Missing current key epoch ${record.currentEpoch}")
            val pruned = record.copy(epochKeysBase64 = mapOf(record.currentEpoch to currentKey))
            saveRecordToKeychain(pruned)
            if (shouldCacheInMemory) {
                cachedRecord = pruned
            }
        }
    }

    override suspend fun resetAndRegenerate(reason: String): Long = mutex.withLock {
        val prevEpoch = cachedRecord?.currentEpoch ?: lastKnownEpoch
        destroyKeyMaterialLocked()
        val freshEpoch = (prevEpoch + 1L).coerceAtLeast(1L)
        val freshRecord = createFreshRecord(freshEpoch)
        saveRecordToKeychain(freshRecord)
        lastKnownEpoch = freshEpoch
        if (shouldCacheInMemory) {
            cachedRecord = freshRecord
        }
        freshEpoch
    }

    override suspend fun destroyKeyMaterial() {
        mutex.withLock {
            destroyKeyMaterialLocked()
        }
    }

    override suspend fun diagnostics(): MaigSecurityDiagnostics = mutex.withLock {
        val record = ensureInitializedLocked()
        val writes = inMemoryWritesSinceRotation ?: record.writesSinceRotation
        MaigSecurityDiagnostics(
            storeName = config.storeName,
            algorithm = MaigCipherAlgorithm.AES256_CTR_HMAC_SHA256,
            securityLevel = MaigSecurityLevel.KEYCHAIN,
            currentKeyEpoch = record.currentEpoch,
            keyCreatedAtEpochMs = record.keyCreatedAtEpochMs,
            writesSinceRotation = writes,
            hardwareBacked = false,
        )
    }

    private fun destroyKeyMaterialLocked() {
        deleteFromKeychain()
        invalidateAuthContextLocked()
        cachedRecord = null
        inMemoryWritesSinceRotation = null
    }

    private fun activeAuthContextLocked(): LAContext? {
        val auth = config.userAuthConfig ?: return null
        val now = currentTimeMillis()
        val validityMs = auth.authValidityDurationSeconds * 1000L
        val existing = currentLaContext
        if (existing == null || (now - laContextCreatedAtMs) >= validityMs) {
            existing?.invalidate()
            val fresh = LAContext().apply {
                touchIDAuthenticationAllowableReuseDuration =
                    auth.authValidityDurationSeconds.coerceAtMost(MAX_APPLE_TOUCH_ID_REUSE_SECONDS).toDouble()
            }
            currentLaContext = fresh
            laContextCreatedAtMs = now
            return fresh
        }
        return existing
    }

    private fun invalidateAuthContextLocked() {
        currentLaContext?.invalidate()
        currentLaContext = null
        laContextCreatedAtMs = 0L
    }

    private fun shouldPersistMetadataWrite(policy: MaigKeyRotationPolicy, writes: Long): Boolean {
        if (policy !is MaigKeyRotationPolicy.Automatic) return false
        return policy.maxWritesBeforeRotation < META_CHECKPOINT_INTERVAL * 2 ||
            writes % META_CHECKPOINT_INTERVAL == 0L
    }

    private fun rotateIfPolicyRequiresLocked(
        record: IosKeychainKeysetRecord,
        policy: MaigKeyRotationPolicy,
    ): IosKeychainKeysetRecord {
        if (policy !is MaigKeyRotationPolicy.Automatic) return record
        val nowMs = currentTimeMillis()
        val ageMs = (nowMs - record.keyCreatedAtEpochMs).coerceAtLeast(0L)
        val maxAgeMs = policy.maxKeyAge.toLong(DurationUnit.MILLISECONDS)
        val writes = inMemoryWritesSinceRotation ?: record.writesSinceRotation
        val trigger = when {
            writes >= policy.maxWritesBeforeRotation -> "write_limit"
            ageMs >= maxAgeMs -> "max_age"
            else -> null
        }
        return if (trigger != null) {
            rotateKeyLocked(record, policy.maxRetainedKeys.coerceAtLeast(2), trigger)
        } else {
            record
        }
    }

    private fun ensureInitializedLocked(): IosKeychainKeysetRecord {
        if (shouldCacheInMemory) {
            cachedRecord?.let { return it }
        }
        val existingBytes = readFromKeychain()
        if (existingBytes != null) {
            return try {
                val parsed = json.decodeFromString(
                    IosKeychainKeysetRecord.serializer(),
                    existingBytes.decodeToString(),
                )
                val syncedWrites = inMemoryWritesSinceRotation ?: parsed.writesSinceRotation
                val synced = parsed.copy(writesSinceRotation = syncedWrites)
                inMemoryWritesSinceRotation = syncedWrites
                lastKnownEpoch = synced.currentEpoch
                if (shouldCacheInMemory) {
                    cachedRecord = synced
                }
                synced
            } catch (e: Throwable) {
                throw MaigStoreTamperedOrCorruptedException(
                    "Corrupted Keychain record for '${config.storeName}'",
                    e,
                )
            } finally {
                existingBytes.wipe()
            }
        }

        val fresh = createFreshRecord(1L)
        saveRecordToKeychain(fresh)
        inMemoryWritesSinceRotation = 0L
        lastKnownEpoch = fresh.currentEpoch
        if (shouldCacheInMemory) {
            cachedRecord = fresh
        }
        config.eventListener?.onEvent(
            MaigSecurityEvent.KeyInitialized(
                storeName = config.storeName,
                securityLevel = MaigSecurityLevel.KEYCHAIN,
                epoch = fresh.currentEpoch,
            )
        )
        return fresh
    }

    private fun rotateKeyLocked(
        current: IosKeychainKeysetRecord,
        maxRetainedKeys: Int,
        trigger: String,
    ): IosKeychainKeysetRecord {
        val newEpoch = current.currentEpoch + 1L
        val newKey = generateRandomBytes(KEY_BYTES)
        val newMap = current.epochKeysBase64.toMutableMap()
        try {
            newMap[newEpoch] = Base64.encode(newKey)
        } finally {
            newKey.wipe()
        }
        val sortedEpochs = newMap.keys.sortedDescending().take(maxRetainedKeys)
        val retainedMap = newMap.filterKeys { it in sortedEpochs }

        val updated = IosKeychainKeysetRecord(
            currentEpoch = newEpoch,
            keyCreatedAtEpochMs = currentTimeMillis(),
            writesSinceRotation = 0L,
            epochKeysBase64 = retainedMap,
        )
        saveRecordToKeychain(updated)
        inMemoryWritesSinceRotation = 0L
        lastKnownEpoch = newEpoch
        if (shouldCacheInMemory) {
            cachedRecord = updated
        }
        config.eventListener?.onEvent(
            MaigSecurityEvent.KeyRotated(
                storeName = config.storeName,
                oldEpoch = current.currentEpoch,
                newEpoch = newEpoch,
                trigger = trigger,
            )
        )
        return updated
    }

    private fun createFreshRecord(epoch: Long): IosKeychainKeysetRecord {
        val rawKey = generateRandomBytes(KEY_BYTES)
        return try {
            IosKeychainKeysetRecord(
                currentEpoch = epoch,
                keyCreatedAtEpochMs = currentTimeMillis(),
                writesSinceRotation = 0L,
                epochKeysBase64 = mapOf(epoch to Base64.encode(rawKey)),
            )
        } finally {
            rawKey.wipe()
        }
    }

    private fun generateRandomBytes(size: Int): ByteArray {
        val out = ByteArray(size)
        val status = out.usePinned { pinned ->
            SecRandomCopyBytes(kSecRandomDefault, size.toULong(), pinned.addressOf(0))
        }
        if (status != 0) {
            throw MaigKeyManagementException("SecRandomCopyBytes failed with status $status")
        }
        return out
    }

    private fun currentTimeMillis(): Long = (NSDate().timeIntervalSince1970 * 1000.0).toLong()

    private fun accessibilityConst(): CFTypeRef? = when (config.iosAccessibility) {
        MaigIosKeychainAccessibility.AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY ->
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        MaigIosKeychainAccessibility.WHEN_UNLOCKED_THIS_DEVICE_ONLY ->
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        MaigIosKeychainAccessibility.WHEN_PASSCODE_SET_THIS_DEVICE_ONLY ->
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
    }

    private fun accessControlProtectionConst(): CFTypeRef? = when (config.iosAccessibility) {
        MaigIosKeychainAccessibility.WHEN_PASSCODE_SET_THIS_DEVICE_ONLY ->
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        MaigIosKeychainAccessibility.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
        MaigIosKeychainAccessibility.AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY ->
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    }

    private fun createAccessControlOrNull(): CFTypeRef? {
        val auth = config.userAuthConfig ?: return null
        val flags = when {
            auth.allowDeviceCredential -> kSecAccessControlUserPresence
            auth.invalidateOnBiometricEnrollment -> kSecAccessControlBiometryCurrentSet
            else -> kSecAccessControlBiometryAny
        }
        return memScoped {
            val error = alloc<CFErrorRefVar>()
            val acl = SecAccessControlCreateWithFlags(
                allocator = null,
                protection = accessControlProtectionConst(),
                flags = flags,
                error = error.ptr,
            )
            if (acl == null) {
                throw MaigKeystoreUnavailableException("Failed to create SecAccessControl for '${config.storeName}'")
            }
            acl
        }
    }

    private fun readFromKeychain(): ByteArray? = memScoped {
        val query = createBaseQuery(includeAuthContext = true)
        CFDictionaryAddValue(query, kSecReturnData, kCFBooleanTrue)
        CFDictionaryAddValue(query, kSecMatchLimit, kSecMatchLimitOne)
        val resultRef = alloc<CFTypeRefVar>()
        val status = SecItemCopyMatching(query, resultRef.ptr)
        CFRelease(query)
        when (status) {
            errSecSuccess -> {
                val data = CFBridgingRelease(resultRef.value) as? NSData ?: return null
                data.toByteArray()
            }
            errSecItemNotFound -> null
            errSecAuthFailed, errSecInteractionNotAllowed, errSecUserCanceled -> {
                invalidateAuthContextLocked()
                throw MaigUserAuthenticationRequiredException(
                    "iOS Keychain authentication required or cancelled (OSStatus=$status)"
                )
            }
            else -> throw MaigKeystoreUnavailableException("Keychain read failed with OSStatus=$status")
        }
    }

    private fun saveRecordToKeychain(record: IosKeychainKeysetRecord) {
        val plainBytes = json.encodeToString(IosKeychainKeysetRecord.serializer(), record).encodeToByteArray()
        val nsData = plainBytes.toNSData()
        plainBytes.wipe()

        val dataRef = CFBridgingRetain(nsData)
        val accessControl = createAccessControlOrNull()
        val addQuery = createBaseQuery(includeAuthContext = true)
        CFDictionaryAddValue(addQuery, kSecValueData, dataRef)
        if (accessControl != null) {
            CFDictionaryAddValue(addQuery, kSecAttrAccessControl, accessControl)
        } else {
            CFDictionaryAddValue(addQuery, kSecAttrAccessible, accessibilityConst())
        }

        var status = SecItemAdd(addQuery, null)
        CFRelease(addQuery)

        if (status == errSecDuplicateItem) {
            val matchQuery = createBaseQuery(includeAuthContext = true)
            val updateAttrs = CFDictionaryCreateMutable(
                null,
                2,
                kCFTypeDictionaryKeyCallBacks.ptr,
                kCFTypeDictionaryValueCallBacks.ptr,
            )
            CFDictionaryAddValue(updateAttrs, kSecValueData, dataRef)
            if (accessControl != null) {
                CFDictionaryAddValue(updateAttrs, kSecAttrAccessControl, accessControl)
            } else {
                CFDictionaryAddValue(updateAttrs, kSecAttrAccessible, accessibilityConst())
            }
            status = SecItemUpdate(matchQuery, updateAttrs)
            CFRelease(matchQuery)
            CFRelease(updateAttrs)
        }
        if (accessControl != null) CFRelease(accessControl)
        if (dataRef != null) CFRelease(dataRef)

        when (status) {
            errSecSuccess -> Unit
            errSecAuthFailed, errSecInteractionNotAllowed, errSecUserCanceled -> {
                invalidateAuthContextLocked()
                throw MaigUserAuthenticationRequiredException(
                    "iOS Keychain authentication required or cancelled on write (OSStatus=$status)"
                )
            }
            else -> throw MaigKeystoreUnavailableException("Keychain write failed with OSStatus=$status")
        }
    }

    private fun deleteFromKeychain() {
        val query = createBaseQuery(includeAuthContext = false)
        val status = SecItemDelete(query)
        CFRelease(query)
        if (status != errSecSuccess && status != errSecItemNotFound) {
            throw MaigKeystoreUnavailableException("Keychain delete failed with OSStatus=$status")
        }
    }

    private fun createBaseQuery(includeAuthContext: Boolean): CFDictionaryRef? {
        val dict = CFDictionaryCreateMutable(
            null,
            6,
            kCFTypeDictionaryKeyCallBacks.ptr,
            kCFTypeDictionaryValueCallBacks.ptr,
        )
        val serviceRef = CFBridgingRetain(serviceName)
        val accountRef = CFBridgingRetain(accountName)
        CFDictionaryAddValue(dict, kSecClass, kSecClassGenericPassword)
        CFDictionaryAddValue(dict, kSecAttrService, serviceRef)
        CFDictionaryAddValue(dict, kSecAttrAccount, accountRef)
        if (includeAuthContext) {
            activeAuthContextLocked()?.let { ctx ->
                val ctxRef = CFBridgingRetain(ctx)
                CFDictionaryAddValue(dict, kSecUseAuthenticationContext, ctxRef)
                if (ctxRef != null) CFRelease(ctxRef)
            }
        }
        if (serviceRef != null) CFRelease(serviceRef)
        if (accountRef != null) CFRelease(accountRef)
        return dict
    }

    private fun ByteArray.toNSData(): NSData = usePinned { pinned ->
        NSData.create(bytes = pinned.addressOf(0), length = size.toULong())
    }

    private fun NSData.toByteArray(): ByteArray {
        val len = length.toInt()
        if (len == 0) return ByteArray(0)
        val out = ByteArray(len)
        val src: COpaquePointer = bytes ?: return ByteArray(0)
        out.usePinned { pinned ->
            memcpy(pinned.addressOf(0), src, length)
        }
        return out
    }
}
