package io.github.maigsecuritycrypto

import kotlin.time.Duration
import kotlin.time.Duration.Companion.days

/**
 * Supported Authenticated Encryption with Associated Data (AEAD) algorithms.
 */
public enum class MaigCipherAlgorithm(public val id: Byte) {
    /**
     * AES-256 in Galois/Counter Mode. Hardware-accelerated on ARMv8 Crypto Extensions and x86 AES-NI.
     */
    AES256_GCM(1),

    /**
     * XChaCha20-Poly1305 with a 192-bit extended nonce. Safe against random-nonce collisions
     * even under high write volumes without hardware AES requirements (Android & JVM).
     */
    XCHACHA20_POLY1305(2),

    /**
     * AES-256-CTR + HMAC-SHA256 Encrypt-then-MAC AEAD. Default on iOS (backed by Apple
     * CommonCrypto) and supported across Android, JVM, and iOS.
     */
    AES256_CTR_HMAC_SHA256(3),
    ;

    public companion object {
        public fun fromId(id: Byte): MaigCipherAlgorithm? = entries.firstOrNull { it.id == id }
    }
}

/**
 * Controls how the store behaves when a keyset or encrypted payload is corrupted or unreadable.
 */
public enum class MaigKeystoreRecoveryPolicy {
    /**
     * Fail closed by throwing [MaigSecurityStorageException]. Never wipes user data or downgrades security.
     * Recommended default for sensitive credentials and tokens.
     */
    STRICT,

    /**
     * If the master key or encrypted store is permanently corrupted (not merely locked by user auth),
     * atomically wipe the corrupted keyset and reset the store to its default value,
     * invoking [MaigSecurityConfig.onRecovery].
     */
    CLEAR_AND_REGENERATE,

    /**
     * Explicit opt-in fallback for devices where `AndroidKeyStore` itself is broken or unavailable.
     * Cannot be combined with [MaigUserAuthConfig]. Derives a local software KEK via HKDF-SHA256
     * over an installation-unique CSPRNG secret stored outside backups, and reports
     * [MaigSecurityLevel.SOFTWARE_FALLBACK] in [MaigEncryptedDataStore.diagnostics].
     */
    EXPLICIT_SOFTWARE_FALLBACK,
}

/**
 * Defines when the active Data Encryption Key (DEK) should be rotated.
 */
public sealed interface MaigKeyRotationPolicy {
    /**
     * Keys are only rotated when [MaigEncryptedDataStore.rotateKeys] is called explicitly.
     */
    public data object Manual : MaigKeyRotationPolicy

    /**
     * Automatically rotates the primary key when either [maxKeyAge] or [maxWritesBeforeRotation]
     * is reached, retaining up to [maxRetainedKeys] historical key epochs (>= 2) for crash-safe reads.
     */
    public data class Automatic(
        public val maxKeyAge: Duration = 90.days,
        public val maxWritesBeforeRotation: Long = 100_000L,
        public val maxRetainedKeys: Int = 2,
    ) : MaigKeyRotationPolicy {
        init {
            require(maxKeyAge.isPositive()) { "maxKeyAge must be positive" }
            require(maxWritesBeforeRotation > 0L) { "maxWritesBeforeRotation must be positive" }
            require(maxRetainedKeys >= 2) {
                "maxRetainedKeys must be at least 2 to prevent data loss if a crash occurs mid-rotation"
            }
        }
    }
}

/**
 * Reports the backing security level of the active master key / keyset.
 */
public enum class MaigSecurityLevel {
    STRONGBOX,
    HARDWARE_TEE,
    KEYCHAIN,
    PASSPHRASE_PBKDF2,
    LOCAL_FILE_KEK,
    SOFTWARE_FALLBACK,
    UNKNOWN,
}

/**
 * Optional biometric / device credential lock configuration for hardware-backed keys.
 *
 * Requires a positive [authValidityDurationSeconds] because per-operation `0`-second keys
 * require explicit `BiometricPrompt.CryptoObject` handling not exposed by DataStore streams.
 */
public data class MaigUserAuthConfig(
    public val authValidityDurationSeconds: Int = 30,
    public val allowDeviceCredential: Boolean = true,
    public val invalidateOnBiometricEnrollment: Boolean = true,
) {
    init {
        require(authValidityDurationSeconds > 0) {
            "authValidityDurationSeconds must be > 0"
        }
    }
}

/**
 * iOS Keychain accessibility policy applied to stored key material.
 */
public enum class MaigIosKeychainAccessibility {
    AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY,
    WHEN_UNLOCKED_THIS_DEVICE_ONLY,
    WHEN_PASSCODE_SET_THIS_DEVICE_ONLY,
}

/**
 * Non-sensitive diagnostic metadata about a recovery event.
 */
public data class MaigRecoveryEvent(
    public val storeName: String,
    public val reason: String,
    public val newEpoch: Long,
)

/**
 * Redacted security telemetry events. Never contains keys, nonces, or plaintext data.
 */
public sealed interface MaigSecurityEvent {
    public val storeName: String

    public data class KeyInitialized(
        override val storeName: String,
        public val securityLevel: MaigSecurityLevel,
        public val epoch: Long,
    ) : MaigSecurityEvent

    public data class StrongBoxFallbackToTee(
        override val storeName: String,
        public val reason: String,
    ) : MaigSecurityEvent

    public data class KeyRotated(
        override val storeName: String,
        public val oldEpoch: Long,
        public val newEpoch: Long,
        public val trigger: String,
    ) : MaigSecurityEvent

    public data class SoftwareFallbackActivated(
        override val storeName: String,
        public val reason: String,
    ) : MaigSecurityEvent

    public data class CorruptionRecovered(
        override val storeName: String,
        public val reason: String,
        public val newEpoch: Long,
    ) : MaigSecurityEvent
}

public fun interface MaigSecurityEventListener {
    public fun onEvent(event: MaigSecurityEvent)
}

/**
 * Runtime posture diagnostics for auditing encryption health in production or debug panels.
 */
public data class MaigSecurityDiagnostics(
    public val storeName: String,
    public val algorithm: MaigCipherAlgorithm,
    public val securityLevel: MaigSecurityLevel,
    public val currentKeyEpoch: Long,
    public val keyCreatedAtEpochMs: Long,
    public val writesSinceRotation: Long,
    public val hardwareBacked: Boolean,
)

/**
 * Security configuration for an [MaigEncryptedDataStore] or [MaigEncryptedPreferences] instance.
 */
public class MaigSecurityConfig(
    public val storeName: String,
    public val algorithm: MaigCipherAlgorithm = defaultCipherAlgorithm(),
    public val keyRotationPolicy: MaigKeyRotationPolicy = MaigKeyRotationPolicy.Automatic(),
    public val recoveryPolicy: MaigKeystoreRecoveryPolicy = MaigKeystoreRecoveryPolicy.STRICT,
    public val preferStrongBox: Boolean = true,
    public val userAuthConfig: MaigUserAuthConfig? = null,
    public val iosAccessibility: MaigIosKeychainAccessibility = MaigIosKeychainAccessibility.AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY,
    public val associatedDataProvider: (() -> ByteArray)? = null,
    public val onRecovery: (suspend (MaigRecoveryEvent) -> Unit)? = null,
    public val eventListener: MaigSecurityEventListener? = null,
) {
    init {
        require(storeName.isNotBlank()) { "storeName must not be blank" }
        require(storeName.length <= 128) { "storeName must be <= 128 characters" }
        require(storeName.all { it.isLetterOrDigit() || it == '_' || it == '-' || it == '.' }) {
            "storeName may only contain letters, digits, '_', '-', or '.'"
        }
        require(!storeName.contains("..")) {
            "storeName must not contain '..'"
        }
        require(!(recoveryPolicy == MaigKeystoreRecoveryPolicy.EXPLICIT_SOFTWARE_FALLBACK && userAuthConfig != null)) {
            "EXPLICIT_SOFTWARE_FALLBACK cannot be combined with userAuthConfig: software fallback keys cannot enforce biometric/device authentication."
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is MaigSecurityConfig) return false
        return storeName == other.storeName &&
            algorithm == other.algorithm &&
            keyRotationPolicy == other.keyRotationPolicy &&
            recoveryPolicy == other.recoveryPolicy &&
            preferStrongBox == other.preferStrongBox &&
            userAuthConfig == other.userAuthConfig &&
            iosAccessibility == other.iosAccessibility
    }

    override fun hashCode(): Int {
        var result = storeName.hashCode()
        result = 31 * result + algorithm.hashCode()
        result = 31 * result + keyRotationPolicy.hashCode()
        result = 31 * result + recoveryPolicy.hashCode()
        result = 31 * result + preferStrongBox.hashCode()
        result = 31 * result + (userAuthConfig?.hashCode() ?: 0)
        result = 31 * result + iosAccessibility.hashCode()
        return result
    }

    override fun toString(): String =
        "MaigSecurityConfig(storeName=$storeName, algorithm=$algorithm, recoveryPolicy=$recoveryPolicy, preferStrongBox=$preferStrongBox)"
}
