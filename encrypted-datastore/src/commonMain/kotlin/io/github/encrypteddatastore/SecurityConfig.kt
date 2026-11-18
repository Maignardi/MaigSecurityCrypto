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
     * atomically wipe the corrupted keyset and store, generate fresh keys, reset to default value,
     * and invoke [SecurityConfig.onRecovery].
     */
    CLEAR_AND_REGENERATE,

    /**
     * Explicit opt-in fallback for devices with broken OEM Keystore implementations.
     * If hardware/TEE Keystore permanently fails keyset wrapping/unwrapping, derives a local
     * software KEK using HKDF/PBKDF2 over an installation-unique CSPRNG secret stored outside backups.
     * Diagnostics will report [SecurityLevel.SOFTWARE_FALLBACK].
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
     * is reached, retaining up to [maxRetainedKeys] historical key epochs for crash-safe reads.
     */
    public data class Automatic(
        public val maxKeyAge: Duration = 90.days,
        public val maxWritesBeforeRotation: Long = 100_000L,
        public val maxRetainedKeys: Int = 2,
    ) : KeyRotationPolicy {
        init {
            require(maxKeyAge.isPositive()) { "maxKeyAge must be positive" }
            require(maxWritesBeforeRotation > 0L) { "maxWritesBeforeRotation must be positive" }
            require(maxRetainedKeys >= 1) { "maxRetainedKeys must be at least 1" }
        }
    }
}

/**
 * Reports the backing security level of the active master key / keyset.
 */
public enum class SecurityLevel {
    STRONGBOX,
    HARDWARE_TEE,
    SECURE_ENCLAVE,
    KEYCHAIN,
    JVM_KEYSTORE,
    SOFTWARE_FALLBACK,
}

/**
 * Optional biometric / device credential lock configuration for hardware-backed keys.
 */
public data class UserAuthConfig(
    public val authValidityDurationSeconds: Int = 30,
    public val allowDeviceCredential: Boolean = true,
    public val invalidateOnBiometricEnrollment: Boolean = true,
) {
    init {
        require(authValidityDurationSeconds >= 0) {
            "authValidityDurationSeconds must be >= 0"
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
public data class SecurityConfig(
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
    }
}
