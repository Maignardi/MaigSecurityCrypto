package io.github.encrypteddatastore

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.security.keystore.UserNotAuthenticatedException
import com.google.crypto.tink.Aead
import java.security.GeneralSecurityException
import java.security.InvalidKeyException
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.MessageDigest
import java.security.ProviderException
import java.security.UnrecoverableKeyException
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

/**
 * Hardware-backed AndroidKeyStore AES-256-GCM AEAD wrapper used as the Key Encryption Key (KEK)
 * to wrap/unwrap the Tink DEK keyset.
 *
 * All KeyStore accesses are serialized through [keyStoreLock] to avoid race conditions
 * observed on several OEM AndroidKeyStore implementations.
 */
internal class AndroidKeyStoreAead(
    private val context: Context,
    private val config: SecurityConfig,
) : Aead {

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val GCM_TAG_BITS = 128
        private val keyStoreLock = Any()

        internal fun buildAlias(packageName: String, storeName: String): String {
            val digest = MessageDigest.getInstance("SHA-256")
                .digest("$packageName:$storeName".encodeToByteArray())
            val hex = digest.joinToString("") { "%02x".format(it) }
            return "edst_mk_${hex.take(24)}"
        }
    }

    internal val alias: String = buildAlias(context.packageName, config.storeName)

    @Volatile
    private var detectedSecurityLevel: SecurityLevel? = null

    fun ensureKeyAndGetSecurityLevel(): SecurityLevel = synchronized(keyStoreLock) {
        try {
            val key = getOrCreateSecretKeyLocked()
            detectSecurityLevelLocked(key)
        } catch (t: Throwable) {
            throw classifyAndroidKeyStoreError("init", t)
        }
    }

    override fun encrypt(plaintext: ByteArray, associatedData: ByteArray): ByteArray {
        return try {
            synchronized(keyStoreLock) {
                val key = getOrCreateSecretKeyLocked()
                val cipher = Cipher.getInstance(TRANSFORMATION)
                cipher.init(Cipher.ENCRYPT_MODE, key)
                if (associatedData.isNotEmpty()) {
                    cipher.updateAAD(associatedData)
                }
                val iv = cipher.iv
                if (iv == null || iv.size !in 12..16) {
                    throw EncryptionException("Unexpected GCM IV length from AndroidKeyStore: ${iv?.size}")
                }
                val encrypted = cipher.doFinal(plaintext)
                val output = ByteArray(1 + iv.size + encrypted.size)
                output[0] = iv.size.toByte()
                iv.copyInto(output, destinationOffset = 1)
                encrypted.copyInto(output, destinationOffset = 1 + iv.size)
                output
            }
        } catch (t: Throwable) {
            throw classifyAndroidKeyStoreError("encrypt", t)
        }
    }

    override fun decrypt(ciphertext: ByteArray, associatedData: ByteArray): ByteArray {
        if (ciphertext.size < 1 + 12 + 16) {
            throw StoreTamperedOrCorruptedException("Keystore ciphertext is truncated")
        }
        val ivLen = ciphertext[0].toInt() and 0xFF
        if (ivLen !in 12..16 || ciphertext.size <= 1 + ivLen + 16) {
            throw StoreTamperedOrCorruptedException("Invalid Keystore IV framing")
        }
        val iv = ciphertext.copyOfRange(1, 1 + ivLen)
        val payload = ciphertext.copyOfRange(1 + ivLen, ciphertext.size)

        return try {
            synchronized(keyStoreLock) {
                val key = getExistingSecretKeyLocked()
                    ?: throw KeystoreUnavailableException("Master key '$alias' not found in AndroidKeyStore")
                val cipher = Cipher.getInstance(TRANSFORMATION)
                cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
                if (associatedData.isNotEmpty()) {
                    cipher.updateAAD(associatedData)
                }
                cipher.doFinal(payload)
            }
        } catch (t: Throwable) {
            throw classifyAndroidKeyStoreError("decrypt", t)
        }
    }

    fun deleteMasterKey() = synchronized(keyStoreLock) {
        try {
            val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            if (ks.containsAlias(alias)) {
                ks.deleteEntry(alias)
            }
            detectedSecurityLevel = null
        } catch (t: Throwable) {
            throw classifyAndroidKeyStoreError("delete", t)
        }
    }

    private fun getExistingSecretKeyLocked(): SecretKey? {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val entry = ks.getEntry(alias, null) as? KeyStore.SecretKeyEntry
        return entry?.secretKey
    }

    private fun getOrCreateSecretKeyLocked(): SecretKey {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val existing = (ks.getEntry(alias, null) as? KeyStore.SecretKeyEntry)?.secretKey
        if (existing != null) {
            return existing
        }

        val tryStrongBox = config.preferStrongBox &&
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
            context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

        if (tryStrongBox) {
            try {
                return generateKey(useStrongBox = true).also {
                    detectedSecurityLevel = SecurityLevel.STRONGBOX
                }
            } catch (e: Throwable) {
                if (isStrongBoxUnavailable(e)) {
                    config.eventListener?.onEvent(
                        SecurityEvent.StrongBoxFallbackToTee(
                            storeName = config.storeName,
                            reason = e.message ?: e::class.simpleName ?: "strongbox_unavailable",
                        )
                    )
                } else {
                    throw classifyAndroidKeyStoreError("generate_strongbox", e)
                }
            }
        }

        return generateKey(useStrongBox = false).also {
            detectedSecurityLevel = detectSecurityLevelLocked(it)
        }
    }

    private fun generateKey(useStrongBox: Boolean): SecretKey {
        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        val specBuilder = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true)

        if (useStrongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            specBuilder.setIsStrongBoxBacked(true)
        }

        config.userAuthConfig?.let { auth ->
            specBuilder.setUserAuthenticationRequired(true)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                val authTypes = if (auth.allowDeviceCredential) {
                    KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
                } else {
                    KeyProperties.AUTH_BIOMETRIC_STRONG
                }
                specBuilder.setUserAuthenticationParameters(auth.authValidityDurationSeconds, authTypes)
            } else {
                @Suppress("DEPRECATION")
                specBuilder.setUserAuthenticationValidityDurationSeconds(
                    auth.authValidityDurationSeconds.coerceAtLeast(1)
                )
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                specBuilder.setInvalidatedByBiometricEnrollment(auth.invalidateOnBiometricEnrollment)
            }
        }

        keyGenerator.init(specBuilder.build())
        return keyGenerator.generateKey()
    }

    private fun detectSecurityLevelLocked(key: SecretKey): SecurityLevel {
        detectedSecurityLevel?.let { return it }
        val resolved = try {
            val factory = SecretKeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE)
            val info = factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                when (info.securityLevel) {
                    KeyProperties.SECURITY_LEVEL_STRONGBOX -> SecurityLevel.STRONGBOX
                    KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> SecurityLevel.HARDWARE_TEE
                    else -> SecurityLevel.SOFTWARE_FALLBACK
                }
            } else {
                @Suppress("DEPRECATION")
                if (info.isInsideSecureHardware) SecurityLevel.HARDWARE_TEE else SecurityLevel.SOFTWARE_FALLBACK
            }
        } catch (_: Throwable) {
            SecurityLevel.HARDWARE_TEE
        }
        detectedSecurityLevel = resolved
        return resolved
    }

    private fun isStrongBoxUnavailable(t: Throwable): Boolean {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && t is StrongBoxUnavailableException) {
            return true
        }
        var cur: Throwable? = t
        while (cur != null) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && cur is StrongBoxUnavailableException) {
                return true
            }
            if (cur is ProviderException && cur.message?.contains("StrongBox", ignoreCase = true) == true) {
                return true
            }
            cur = cur.cause
        }
        return false
    }

    private fun classifyAndroidKeyStoreError(op: String, t: Throwable): SecurityStorageException {
        if (t is SecurityStorageException) return t
        if (t is UserNotAuthenticatedException || t.cause is UserNotAuthenticatedException) {
            return UserAuthenticationRequiredException(
                "User authentication required to $op key for '${config.storeName}'",
                t,
            )
        }
        if (t is android.security.keystore.KeyPermanentlyInvalidatedException ||
            t.cause is android.security.keystore.KeyPermanentlyInvalidatedException
        ) {
            return KeyPermanentlyInvalidatedException(
                "Hardware key permanently invalidated for '${config.storeName}'",
                t,
            )
        }
        if (t is AEADBadTagException || t.cause is AEADBadTagException) {
            return StoreTamperedOrCorruptedException(
                "AndroidKeyStore AEAD tag mismatch during $op for '${config.storeName}'",
                t,
            )
        }
        if (t is UnrecoverableKeyException ||
            t is InvalidKeyException ||
            t is KeyStoreException ||
            t is ProviderException ||
            t is GeneralSecurityException
        ) {
            return KeystoreUnavailableException(
                "AndroidKeyStore failed during $op for '${config.storeName}': ${t.message}",
                t,
            )
        }
        return KeystoreUnavailableException(
            "Unexpected AndroidKeyStore failure during $op for '${config.storeName}'",
            t,
        )
    }
}
