@file:OptIn(
    kotlinx.cinterop.ExperimentalForeignApi::class,
    kotlinx.cinterop.BetaInteropApi::class,
    kotlin.io.encoding.ExperimentalEncodingApi::class,
)

package io.github.encrypteddatastore

import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.AES
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
import platform.CoreFoundation.CFDictionaryAddValue
import platform.CoreFoundation.CFDictionaryCreateMutable
import platform.CoreFoundation.CFDictionaryRef
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
import platform.Security.SecItemAdd
import platform.Security.SecItemCopyMatching
import platform.Security.SecItemDelete
import platform.Security.SecItemUpdate
import platform.Security.SecRandomCopyBytes
import platform.Security.errSecDuplicateItem
import platform.Security.errSecItemNotFound
import platform.Security.errSecSuccess
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
 * iOS Keychain-backed [KeyManager] using Apple native cryptography via `cryptography-provider-apple`
 * and `ThisDeviceOnly` Keychain items (`SecItem*`).
 */
internal class IosKeychainKeyManager(
    private val context: PlatformStorageContext,
    private val config: SecurityConfig,
) : KeyManager {

    private companion object {
        const val KEY_BYTES = 32
    }

    private val mutex = Mutex()
    private val json = Json { ignoreUnknownKeys = true }
    private val provider = CryptographyProvider.Default
    private val aesGcm = provider.get(AES.GCM)
    private val serviceName = context.resolvedServiceName()
    private val accountName = "edst_dek_${config.storeName}"

    private var cachedRecord: IosKeychainKeysetRecord? = null

    override val securityLevel: SecurityLevel = SecurityLevel.KEYCHAIN

    override suspend fun currentEpoch(): Long = mutex.withLock {
        ensureInitializedLocked().currentEpoch
    }

    override suspend fun keyCreatedAtEpochMs(): Long = mutex.withLock {
        ensureInitializedLocked().keyCreatedAtEpochMs
    }

    override suspend fun writesSinceRotation(): Long = mutex.withLock {
        ensureInitializedLocked().writesSinceRotation
    }

    override suspend fun encrypt(plaintext: ByteArray, associatedData: ByteArray): EncryptedPayload =
        mutex.withLock {
            val record = ensureInitializedLocked()
            val keyBase64 = record.epochKeysBase64[record.currentEpoch]
                ?: throw KeyManagementException("Missing DEK for epoch ${record.currentEpoch}")
            val rawKey = Base64.decode(keyBase64)
            try {
                val key = aesGcm.keyDecoder().decodeFromByteArray(AES.Key.Format.RAW, rawKey)
                val ciphertext = key.cipher().encrypt(plaintext, associatedData)
                val updated = record.copy(writesSinceRotation = record.writesSinceRotation + 1L)
                saveRecordToKeychain(updated)
                cachedRecord = updated
                EncryptedPayload(
                    keyEpoch = record.currentEpoch,
                    algorithm = CipherAlgorithm.AES256_GCM,
                    ciphertext = ciphertext,
                )
            } catch (e: SecurityStorageException) {
                throw e
            } catch (e: Throwable) {
                throw EncryptionException("iOS AEAD encryption failed for '${config.storeName}'", e)
            } finally {
                rawKey.wipe()
            }
        }

    override suspend fun decrypt(
        ciphertext: ByteArray,
        algorithm: CipherAlgorithm,
        keyEpoch: Long,
        associatedData: ByteArray,
    ): ByteArray = mutex.withLock {
        val record = ensureInitializedLocked()
        val keyBase64 = record.epochKeysBase64[keyEpoch]
            ?: throw StoreTamperedOrCorruptedException(
                "No retained DEK for epoch $keyEpoch in '${config.storeName}'"
            )
        val rawKey = Base64.decode(keyBase64)
        try {
            val key = aesGcm.keyDecoder().decodeFromByteArray(AES.Key.Format.RAW, rawKey)
            key.cipher().decrypt(ciphertext, associatedData)
        } catch (e: Throwable) {
            throw StoreTamperedOrCorruptedException(
                "iOS AEAD authentication failed for '${config.storeName}' (epoch=$keyEpoch)",
                e,
            )
        } finally {
            rawKey.wipe()
        }
    }

    override suspend fun rotateIfPolicyRequires(policy: KeyRotationPolicy): Long = mutex.withLock {
        val record = ensureInitializedLocked()
        if (policy is KeyRotationPolicy.Automatic) {
            val nowMs = currentTimeMillis()
            val ageMs = (nowMs - record.keyCreatedAtEpochMs).coerceAtLeast(0L)
            val maxAgeMs = policy.maxKeyAge.toLong(DurationUnit.MILLISECONDS)
            val trigger = when {
                record.writesSinceRotation >= policy.maxWritesBeforeRotation -> "write_limit"
                ageMs >= maxAgeMs -> "max_age"
                else -> null
            }
            if (trigger != null) {
                return@withLock rotateKeyLocked(policy.maxRetainedKeys, trigger)
            }
        }
        record.currentEpoch
    }

    override suspend fun rotateKey(maxRetainedKeys: Int, trigger: String): Long = mutex.withLock {
        ensureInitializedLocked()
        rotateKeyLocked(maxRetainedKeys, trigger)
    }

    override suspend fun pruneHistoricalKeys() {
        mutex.withLock {
            val record = ensureInitializedLocked()
            val currentKey = record.epochKeysBase64[record.currentEpoch]
                ?: throw KeyManagementException("Missing current key epoch ${record.currentEpoch}")
            val pruned = record.copy(epochKeysBase64 = mapOf(record.currentEpoch to currentKey))
            saveRecordToKeychain(pruned)
            cachedRecord = pruned
        }
    }

    override suspend fun resetAndRegenerate(reason: String): Long = mutex.withLock {
        val prevEpoch = cachedRecord?.currentEpoch ?: 0L
        deleteFromKeychain()
        cachedRecord = null
        val freshEpoch = (prevEpoch + 1L).coerceAtLeast(1L)
        val freshRecord = createFreshRecord(freshEpoch)
        saveRecordToKeychain(freshRecord)
        cachedRecord = freshRecord
        freshEpoch
    }

    override suspend fun diagnostics(): SecurityDiagnostics = mutex.withLock {
        val record = ensureInitializedLocked()
        SecurityDiagnostics(
            storeName = config.storeName,
            algorithm = CipherAlgorithm.AES256_GCM,
            securityLevel = securityLevel,
            currentKeyEpoch = record.currentEpoch,
            keyCreatedAtEpochMs = record.keyCreatedAtEpochMs,
            writesSinceRotation = record.writesSinceRotation,
            hardwareBacked = true,
        )
    }

    private fun ensureInitializedLocked(): IosKeychainKeysetRecord {
        cachedRecord?.let { return it }
        val existingBytes = readFromKeychain()
        if (existingBytes != null) {
            return try {
                val parsed = json.decodeFromString(
                    IosKeychainKeysetRecord.serializer(),
                    existingBytes.decodeToString(),
                )
                cachedRecord = parsed
                parsed
            } catch (e: Throwable) {
                throw KeyManagementException("Corrupted Keychain record for '${config.storeName}'", e)
            } finally {
                existingBytes.wipe()
            }
        }

        val fresh = createFreshRecord(1L)
        saveRecordToKeychain(fresh)
        cachedRecord = fresh
        config.eventListener?.onEvent(
            SecurityEvent.KeyInitialized(
                storeName = config.storeName,
                securityLevel = securityLevel,
                epoch = fresh.currentEpoch,
            )
        )
        return fresh
    }

    private fun rotateKeyLocked(maxRetainedKeys: Int, trigger: String): Long {
        val current = cachedRecord!!
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
        cachedRecord = updated
        config.eventListener?.onEvent(
            SecurityEvent.KeyRotated(
                storeName = config.storeName,
                oldEpoch = current.currentEpoch,
                newEpoch = newEpoch,
                trigger = trigger,
            )
        )
        return newEpoch
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
            throw KeyManagementException("SecRandomCopyBytes failed with status $status")
        }
        return out
    }

    private fun currentTimeMillis(): Long = (NSDate().timeIntervalSince1970 * 1000.0).toLong()

    private fun accessibilityConst(): CFTypeRef? = when (config.iosAccessibility) {
        IosKeychainAccessibility.AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY ->
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        IosKeychainAccessibility.WHEN_UNLOCKED_THIS_DEVICE_ONLY ->
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        IosKeychainAccessibility.WHEN_PASSCODE_SET_THIS_DEVICE_ONLY ->
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
    }

    private fun readFromKeychain(): ByteArray? = memScoped {
        val query = createBaseQuery()
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
            else -> throw KeystoreUnavailableException("Keychain read failed with OSStatus=$status")
        }
    }

    private fun saveRecordToKeychain(record: IosKeychainKeysetRecord) {
        val plainBytes = json.encodeToString(IosKeychainKeysetRecord.serializer(), record).encodeToByteArray()
        val nsData = plainBytes.toNSData()
        plainBytes.wipe()

        val dataRef = CFBridgingRetain(nsData)
        val addQuery = createBaseQuery()
        CFDictionaryAddValue(addQuery, kSecValueData, dataRef)
        CFDictionaryAddValue(addQuery, kSecAttrAccessible, accessibilityConst())

        var status = SecItemAdd(addQuery, null)
        CFRelease(addQuery)

        if (status == errSecDuplicateItem) {
            val matchQuery = createBaseQuery()
            val updateAttrs = CFDictionaryCreateMutable(
                null,
                2,
                kCFTypeDictionaryKeyCallBacks.ptr,
                kCFTypeDictionaryValueCallBacks.ptr,
            )
            CFDictionaryAddValue(updateAttrs, kSecValueData, dataRef)
            CFDictionaryAddValue(updateAttrs, kSecAttrAccessible, accessibilityConst())
            status = SecItemUpdate(matchQuery, updateAttrs)
            CFRelease(matchQuery)
            CFRelease(updateAttrs)
        }
        if (dataRef != null) CFRelease(dataRef)

        if (status != errSecSuccess) {
            throw KeystoreUnavailableException("Keychain write failed with OSStatus=$status")
        }
    }

    private fun deleteFromKeychain() {
        val query = createBaseQuery()
        val status = SecItemDelete(query)
        CFRelease(query)
        if (status != errSecSuccess && status != errSecItemNotFound) {
            throw KeystoreUnavailableException("Keychain delete failed with OSStatus=$status")
        }
    }

    private fun createBaseQuery(): CFDictionaryRef? {
        val dict = CFDictionaryCreateMutable(
            null,
            5,
            kCFTypeDictionaryKeyCallBacks.ptr,
            kCFTypeDictionaryValueCallBacks.ptr,
        )
        val serviceRef = CFBridgingRetain(serviceName)
        val accountRef = CFBridgingRetain(accountName)
        CFDictionaryAddValue(dict, kSecClass, kSecClassGenericPassword)
        CFDictionaryAddValue(dict, kSecAttrService, serviceRef)
        CFDictionaryAddValue(dict, kSecAttrAccount, accountRef)
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
