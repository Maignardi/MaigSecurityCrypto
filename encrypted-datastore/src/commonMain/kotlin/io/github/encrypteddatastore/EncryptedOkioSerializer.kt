package io.github.encrypteddatastore

import androidx.datastore.core.CorruptionException
import androidx.datastore.core.okio.OkioSerializer
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.KSerializer
import kotlinx.serialization.json.Json
import okio.BufferedSink
import okio.BufferedSource
import kotlin.concurrent.Volatile

internal data class EncryptedBox<T>(
    val value: T,
    val keyEpoch: Long,
)

internal class EncryptedOkioSerializer<T>(
    private val rawDefaultValue: T,
    private val kSerializer: KSerializer<T>,
    private val json: Json,
    private val config: SecurityConfig,
    private val keyManager: KeyManager,
) : OkioSerializer<EncryptedBox<T>> {

    private val recoveryMutex = Mutex()

    @Volatile
    private var pendingRecoveryEpoch: Long? = null

    internal fun peekPendingRecoveryEpoch(): Long = pendingRecoveryEpoch ?: 0L

    override val defaultValue: EncryptedBox<T>
        get() = EncryptedBox(value = rawDefaultValue, keyEpoch = 0L)

    override suspend fun readFrom(source: BufferedSource): EncryptedBox<T> {
        val rawBytes = source.readByteArray()
        if (rawBytes.isEmpty()) {
            return handleReadFailure(
                StoreTamperedOrCorruptedException(
                    "Encrypted store '${config.storeName}' is empty (possible truncation)."
                )
            )
        }

        return try {
            val envelope = EncryptedEnvelopeCodec.decode(rawBytes)
            val aad = EncryptedEnvelopeCodec.buildAssociatedData(
                header = envelope.header,
                storeName = config.storeName,
                userAad = config.associatedDataProvider?.invoke(),
            )
            val plaintext = keyManager.decrypt(
                ciphertext = envelope.ciphertext,
                algorithm = envelope.algorithm,
                keyEpoch = envelope.keyEpoch,
                associatedData = aad,
            )
            try {
                val jsonText = plaintext.decodeToString()
                val decodedValue = json.decodeFromString(kSerializer, jsonText)
                EncryptedBox(value = decodedValue, keyEpoch = envelope.keyEpoch)
            } finally {
                plaintext.wipe()
            }
        } catch (authRequired: UserAuthenticationRequiredException) {
            // Never wipe or treat locked device / missing biometric auth as corruption.
            throw authRequired
        } catch (tampered: StoreTamperedOrCorruptedException) {
            handleReadFailure(tampered)
        } catch (invalidated: KeyPermanentlyInvalidatedException) {
            handleReadFailure(invalidated)
        } catch (decryptError: DecryptionException) {
            handleReadFailure(decryptError)
        } catch (e: Exception) {
            if (e is SecurityStorageException) throw e
            handleReadFailure(
                StoreTamperedOrCorruptedException(
                    "Failed to decode encrypted store '${config.storeName}'",
                    e,
                )
            )
        }
    }

    override suspend fun writeTo(t: EncryptedBox<T>, sink: BufferedSink) {
        val jsonBytes = json.encodeToString(kSerializer, t.value).encodeToByteArray()
        try {
            val epoch = keyManager.currentEpoch()
            val header = EncryptedEnvelopeCodec.buildHeader(config.algorithm, epoch)
            val aad = EncryptedEnvelopeCodec.buildAssociatedData(
                header = header,
                storeName = config.storeName,
                userAad = config.associatedDataProvider?.invoke(),
            )
            val encrypted = keyManager.encrypt(jsonBytes, aad)
            val finalHeader = if (encrypted.keyEpoch == epoch && encrypted.algorithm == config.algorithm) {
                header
            } else {
                // Ensure envelope header always matches exact keyEpoch/algorithm used.
                EncryptedEnvelopeCodec.buildHeader(encrypted.algorithm, encrypted.keyEpoch)
            }
            // Note: encrypt() uses the AAD computed from the active header; assert consistency.
            check(finalHeader.contentEquals(header)) {
                "Envelope header diverged during write encryption"
            }
            val envelopeBytes = EncryptedEnvelopeCodec.encode(header, encrypted.ciphertext)
            sink.write(envelopeBytes)
            pendingRecoveryEpoch = null
        } finally {
            jsonBytes.wipe()
        }
    }

    private suspend fun handleReadFailure(error: SecurityStorageException): Nothing {
        when (config.recoveryPolicy) {
            KeystoreRecoveryPolicy.STRICT,
            KeystoreRecoveryPolicy.EXPLICIT_SOFTWARE_FALLBACK -> throw error

            KeystoreRecoveryPolicy.CLEAR_AND_REGENERATE -> {
                recoveryMutex.withLock {
                    if (pendingRecoveryEpoch == null) {
                        val reason = error.message ?: error::class.simpleName ?: "corrupted_store"
                        val newEpoch = keyManager.resetAndRegenerate(reason)
                        pendingRecoveryEpoch = newEpoch
                        config.eventListener?.onEvent(
                            SecurityEvent.CorruptionRecovered(
                                storeName = config.storeName,
                                reason = reason,
                                newEpoch = newEpoch,
                            )
                        )
                        config.onRecovery?.invoke(
                            RecoveryEvent(
                                storeName = config.storeName,
                                reason = reason,
                                newEpoch = newEpoch,
                            )
                        )
                    }
                }
                throw CorruptionException(
                    "Encrypted store '${config.storeName}' was corrupted: ${error.message}",
                    error,
                )
            }
        }
    }
}
