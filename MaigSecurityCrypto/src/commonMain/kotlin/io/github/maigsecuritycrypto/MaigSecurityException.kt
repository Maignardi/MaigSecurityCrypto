package io.github.maigsecuritycrypto

/**
 * Base exception for all cryptographic and secure storage failures in MaigSecurityCrypto.
 */
public open class MaigSecurityStorageException(
    message: String,
    cause: Throwable? = null,
) : Exception(message, cause)

/**
 * Thrown when key creation, loading, wrapping, or rotation fails.
 */
public open class MaigKeyManagementException(
    message: String,
    cause: Throwable? = null,
) : MaigSecurityStorageException(message, cause)

/**
 * Thrown when payload encryption fails.
 */
public class MaigEncryptionException(
    message: String,
    cause: Throwable? = null,
) : MaigSecurityStorageException(message, cause)

/**
 * Thrown when payload decryption fails.
 */
public open class MaigDecryptionException(
    message: String,
    cause: Throwable? = null,
) : MaigSecurityStorageException(message, cause)

/**
 * Thrown when the encrypted file header, AEAD authentication tag, or associated data
 * fails verification (indicating tampering, file swapping, truncation, or corruption).
 */
public class MaigStoreTamperedOrCorruptedException(
    message: String,
    cause: Throwable? = null,
) : MaigDecryptionException(message, cause)

/**
 * Thrown when the platform hardware keystore is unavailable or malfunctioning
 * under [MaigKeystoreRecoveryPolicy.STRICT].
 */
public class MaigKeystoreUnavailableException(
    message: String,
    cause: Throwable? = null,
) : MaigKeyManagementException(message, cause)

/**
 * Thrown when the underlying key requires recent user authentication (biometric or device credential).
 *
 * This error is transient and MUST NOT trigger corruption recovery or store wiping.
 */
public class MaigUserAuthenticationRequiredException(
    message: String,
    cause: Throwable? = null,
) : MaigKeyManagementException(message, cause)

/**
 * Thrown when a hardware-backed key has been permanently invalidated (for example,
 * after new biometric enrollment or lock screen removal).
 */
public class MaigKeyPermanentlyInvalidatedException(
    message: String,
    cause: Throwable? = null,
) : MaigKeyManagementException(message, cause)
