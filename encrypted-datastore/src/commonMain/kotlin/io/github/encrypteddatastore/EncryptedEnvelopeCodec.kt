package io.github.encrypteddatastore

import okio.Buffer

/**
 * Encrypted binary envelope format:
 * - Bytes 0..3: Magic `"EDST"` (`0x45, 0x44, 0x53, 0x54`)
 * - Byte 4: Format version (`0x01`)
 * - Byte 5: [CipherAlgorithm.id]
 * - Bytes 6..13: `keyEpoch` (big-endian 64-bit integer)
 * - Bytes 14..N: AEAD ciphertext (includes implementation-specific nonce/IV and authentication tag)
 *
 * The 14-byte header is bound into the AEAD Associated Data (AAD) together with the
 * domain tag, canonical store name, and optional caller-supplied AAD so any header
 * modification, algorithm downgrade, or cross-store ciphertext swap fails authentication.
 */
internal object EncryptedEnvelopeCodec {
    private val MAGIC = byteArrayOf(0x45, 0x44, 0x53, 0x54) // "EDST"
    internal const val FORMAT_VERSION: Byte = 0x01
    internal const val HEADER_SIZE: Int = 14
    private val AAD_DOMAIN = "EDST_AAD_V1".encodeToByteArray()

    data class DecodedEnvelope(
        val version: Byte,
        val algorithm: CipherAlgorithm,
        val keyEpoch: Long,
        val header: ByteArray,
        val ciphertext: ByteArray,
    )

    fun buildHeader(algorithm: CipherAlgorithm, keyEpoch: Long): ByteArray {
        val buffer = Buffer()
        buffer.write(MAGIC)
        buffer.writeByte(FORMAT_VERSION.toInt())
        buffer.writeByte(algorithm.id.toInt())
        buffer.writeLong(keyEpoch)
        return buffer.readByteArray()
    }

    fun buildAssociatedData(
        header: ByteArray,
        storeName: String,
        userAad: ByteArray?,
    ): ByteArray {
        require(header.size == HEADER_SIZE) { "Invalid envelope header size: ${header.size}" }
        val storeNameBytes = storeName.encodeToByteArray()
        val extraAad = userAad ?: ByteArray(0)
        val buffer = Buffer()
        buffer.writeInt(AAD_DOMAIN.size)
        buffer.write(AAD_DOMAIN)
        buffer.writeInt(storeNameBytes.size)
        buffer.write(storeNameBytes)
        buffer.write(header)
        buffer.writeInt(extraAad.size)
        buffer.write(extraAad)
        return buffer.readByteArray()
    }

    fun encode(header: ByteArray, ciphertext: ByteArray): ByteArray {
        require(header.size == HEADER_SIZE) { "Invalid envelope header size: ${header.size}" }
        val out = ByteArray(HEADER_SIZE + ciphertext.size)
        header.copyInto(out, destinationOffset = 0)
        ciphertext.copyInto(out, destinationOffset = HEADER_SIZE)
        return out
    }

    fun decode(bytes: ByteArray): DecodedEnvelope {
        if (bytes.size <= HEADER_SIZE) {
            throw StoreTamperedOrCorruptedException(
                "Encrypted store payload is truncated or empty (${bytes.size} bytes)"
            )
        }
        for (i in MAGIC.indices) {
            if (bytes[i] != MAGIC[i]) {
                throw StoreTamperedOrCorruptedException("Invalid encrypted envelope magic header")
            }
        }
        val version = bytes[4]
        if (version != FORMAT_VERSION) {
            throw StoreTamperedOrCorruptedException("Unsupported envelope version: $version")
        }
        val algorithmId = bytes[5]
        val algorithm = CipherAlgorithm.fromId(algorithmId)
            ?: throw StoreTamperedOrCorruptedException("Unknown cipher algorithm id: $algorithmId")

        val buffer = Buffer().write(bytes, 6, 8)
        val keyEpoch = buffer.readLong()
        if (keyEpoch < 0L) {
            throw StoreTamperedOrCorruptedException("Negative key epoch in envelope: $keyEpoch")
        }

        val header = bytes.copyOfRange(0, HEADER_SIZE)
        val ciphertext = bytes.copyOfRange(HEADER_SIZE, bytes.size)
        return DecodedEnvelope(
            version = version,
            algorithm = algorithm,
            keyEpoch = keyEpoch,
            header = header,
            ciphertext = ciphertext,
        )
    }
}

/**
 * Overwrites sensitive transient buffers with zeros after use.
 */
public fun ByteArray.wipe() {
    fill(0)
}
