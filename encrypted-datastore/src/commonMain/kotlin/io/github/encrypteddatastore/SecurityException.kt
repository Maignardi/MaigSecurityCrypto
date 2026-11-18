package io.github.encrypteddatastore

/**
 * Base exception for all cryptographic and secure storage failures in EncryptedDataStore.
 */
public open class SecurityStorageException(
    message: String,
    cause: Throwable? = null,
) : Exception(message, cause)

/**
 * Thrown when key creation, loading, wrapping, or rotation fails.
 */
public open class KeyManagementException(
    message: String,
    cause: Throwable? = null,
) : SecurityStorageException(message, cause)

/**
 * Thrown when payload encryption fails.
 */
public class EncryptionException(
    message: String,
    cause: Throwable? = null,
) : SecurityStorageException(message, cause)

/**
 * Thrown when payload decryption fails.
 */
public open class DecryptionException(
    message: String,
    cause: Throwable? = null,
) : SecurityStorageException(message, cause)

/**
 * Thrown when the encrypted file header, AEAD authentication tag, or associated data
 * fails verification (indicating tampering, file swapping, truncation, or corruption).
 */
public class StoreTamperedOrCorruptedException(
    message: String,
    cause: Throwable? = null,
) : DecryptionException(message, cause)

/**
 * Thrown when the platform hardware keystore is unavailable or malfunctioning
 * under [KeystoreRecoveryPolicy.STRICT].
 */
public class KeystoreUnavailableException(
    message: String,
    cause: Throwable? = null,
) : KeyManagementException(message, cause)

/**
 * Thrown when the underlying key requires recent user authentication (biometric or device credential).
 *
 * This error is transient and MUST NOT trigger corruption recovery or store wiping.
 */
public class UserAuthenticationRequiredException(
    message: String,
    cause: Throwable? = null,
) : KeyManagementException(message, cause)

/**
 * Thrown when a hardware-backed key has been permanently invalidated (for example,
 * after new biometric enrollment or lock screen removal).
 */
public class KeyPermanentlyInvalidatedException(
    message: String,
    cause: Throwable? = null,
) : KeyManagementException(message, cause)
