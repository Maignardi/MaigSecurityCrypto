package io.github.encrypteddatastore

import kotlin.time.Duration
import kotlin.time.Duration.Companion.days

/**
 * Supported Authenticated Encryption with Associated Data (AEAD) algorithms.
 */
public enum class CipherAlgorithm(public val id: Byte) {
    /**
     * AES-256 in Galois/Counter Mode. Hardware-accelerated on ARMv8 Crypto Extensions and x86 AES-NI.
     */
    AES256_GCM(1),

    /**
     * XChaCha20-Poly1305 with a 192-bit extended nonce. Safe against random-nonce collisions
     * even under high write volumes without hardware AES requirements.
     */
    XCHACHA20_POLY1305(2),
    ;

    public companion object {
        public fun fromId(id: Byte): CipherAlgorithm? = entries.firstOrNull { it.id == id }
    }
}

/**
 * Controls how the store behaves when a keyset or encrypted payload is corrupted or unreadable.
 */
public enum class KeystoreRecoveryPolicy {
    /**
     * Fail closed by throwing [SecurityStorageException]. Never wipes user data or downgrades security.
     * Recommended default for sensitive credentials and tokens.
     */
    STRICT,

    /**
     * If the master key or encrypted store is permanently corrupted (not merely locked by user auth),
     * atomically wipe the corrupted keyset and reset the store to its default value,
     * invoking [SecurityConfig.onRecovery].
     */
    CLEAR_AND_REGENERATE,

    /**
     * Explicit opt-in fallback for devices where `AndroidKeyStore` itself is broken or unavailable.
     * Cannot be combined with [UserAuthConfig]. Derives a local software KEK via HKDF-SHA256
     * over an installation-unique CSPRNG secret stored outside backups, and reports
     * [SecurityLevel.SOFTWARE_FALLBACK] in [EncryptedDataStore.diagnostics].
     */
    EXPLICIT_SOFTWARE_FALLBACK,
}

/**
 * Defines when the active Data Encryption Key (DEK) should be rotated.
 */
public sealed interface KeyRotationPolicy {
    /**
     * Keys are only rotated when [EncryptedDataStore.rotateKeys] is called explicitly.
     */
    public data object Manual : KeyRotationPolicy

    /**
     * Automatically rotates the primary key when either [maxKeyAge] or [maxWritesBeforeRotation]
     * is reached, retaining up to [maxRetainedKeys] historical key epochs (>= 2) for crash-safe reads.
     */
    public data class Automatic(
        public val maxKeyAge: Duration = 90.days,
        public val maxWritesBeforeRotation: Long = 100_000L,
        public val maxRetainedKeys: Int = 2,
    ) : KeyRotationPolicy {
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
public enum class SecurityLevel {
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
public data class UserAuthConfig(
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
public enum class IosKeychainAccessibility {
    AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY,
    WHEN_UNLOCKED_THIS_DEVICE_ONLY,
    WHEN_PASSCODE_SET_THIS_DEVICE_ONLY,
}

/**
 * Non-sensitive diagnostic metadata about a recovery event.
 */
public data class RecoveryEvent(
    public val storeName: String,
    public val reason: String,
    public val newEpoch: Long,
)

/**
 * Redacted security telemetry events. Never contains keys, nonces, or plaintext data.
 */
public sealed interface SecurityEvent {
    public val storeName: String

    public data class KeyInitialized(
        override val storeName: String,
        public val securityLevel: SecurityLevel,
        public val epoch: Long,
    ) : SecurityEvent

    public data class StrongBoxFallbackToTee(
        override val storeName: String,
        public val reason: String,
    ) : SecurityEvent

    public data class KeyRotated(
        override val storeName: String,
        public val oldEpoch: Long,
        public val newEpoch: Long,
        public val trigger: String,
    ) : SecurityEvent

    public data class SoftwareFallbackActivated(
        override val storeName: String,
        public val reason: String,
    ) : SecurityEvent

    public data class CorruptionRecovered(
        override val storeName: String,
        public val reason: String,
        public val newEpoch: Long,
    ) : SecurityEvent
}

public fun interface SecurityEventListener {
    public fun onEvent(event: SecurityEvent)
}

/**
 * Runtime posture diagnostics for auditing encryption health in production or debug panels.
 */
public data class SecurityDiagnostics(
    public val storeName: String,
    public val algorithm: CipherAlgorithm,
    public val securityLevel: SecurityLevel,
    public val currentKeyEpoch: Long,
    public val keyCreatedAtEpochMs: Long,
    public val writesSinceRotation: Long,
    public val hardwareBacked: Boolean,
)

/**
 * Security configuration for an [EncryptedDataStore] or [EncryptedPreferences] instance.
 */
public class SecurityConfig(
    public val storeName: String,
    public val algorithm: CipherAlgorithm = CipherAlgorithm.AES256_GCM,
    public val keyRotationPolicy: KeyRotationPolicy = KeyRotationPolicy.Automatic(),
    public val recoveryPolicy: KeystoreRecoveryPolicy = KeystoreRecoveryPolicy.STRICT,
    public val preferStrongBox: Boolean = true,
    public val userAuthConfig: UserAuthConfig? = null,
    public val iosAccessibility: IosKeychainAccessibility = IosKeychainAccessibility.AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY,
    public val associatedDataProvider: (() -> ByteArray)? = null,
    public val onRecovery: (suspend (RecoveryEvent) -> Unit)? = null,
    public val eventListener: SecurityEventListener? = null,
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
        require(!(recoveryPolicy == KeystoreRecoveryPolicy.EXPLICIT_SOFTWARE_FALLBACK && userAuthConfig != null)) {
            "EXPLICIT_SOFTWARE_FALLBACK cannot be combined with userAuthConfig: software fallback keys cannot enforce biometric/device authentication."
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is SecurityConfig) return false
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
        "SecurityConfig(storeName=$storeName, algorithm=$algorithm, recoveryPolicy=$recoveryPolicy, preferStrongBox=$preferStrongBox)"
}
