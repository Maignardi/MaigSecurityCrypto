package io.github.maigsecuritycrypto

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.seconds

class EncryptedEnvelopeCodecTest {

    @Test
    fun `encodes and decodes envelope header accurately across algorithms and epochs`() {
        for (alg in MaigCipherAlgorithm.entries) {
            for (epoch in listOf(0L, 1L, 42L, Long.MAX_VALUE)) {
                val header = EncryptedEnvelopeCodec.buildHeader(alg, epoch)
                assertEquals(EncryptedEnvelopeCodec.HEADER_SIZE, header.size)

                val ciphertext = byteArrayOf(10, 20, 30, 40)
                val full = EncryptedEnvelopeCodec.encode(header, ciphertext)
                val decoded = EncryptedEnvelopeCodec.decode(full)

                assertEquals(EncryptedEnvelopeCodec.FORMAT_VERSION, decoded.version)
                assertEquals(alg, decoded.algorithm)
                assertEquals(epoch, decoded.keyEpoch)
                assertContentEquals(header, decoded.header)
                assertContentEquals(ciphertext, decoded.ciphertext)
            }
        }
    }

    @Test
    fun `rejects invalid magic version algorithm negative epoch and truncated payloads`() {
        val validHeader = EncryptedEnvelopeCodec.buildHeader(MaigCipherAlgorithm.AES256_GCM, 1L)
        val valid = EncryptedEnvelopeCodec.encode(validHeader, byteArrayOf(1, 2, 3))

        // Truncated (<= 14 bytes)
        assertFailsWith<MaigStoreTamperedOrCorruptedException> {
            EncryptedEnvelopeCodec.decode(ByteArray(0))
        }
        assertFailsWith<MaigStoreTamperedOrCorruptedException> {
            EncryptedEnvelopeCodec.decode(validHeader)
        }

        // Bad magic
        val badMagic = valid.copyOf().apply { this[0] = 'X'.code.toByte() }
        assertFailsWith<MaigStoreTamperedOrCorruptedException> {
            EncryptedEnvelopeCodec.decode(badMagic)
        }

        // Unsupported version
        val badVersion = valid.copyOf().apply { this[4] = 0x7F }
        assertFailsWith<MaigStoreTamperedOrCorruptedException> {
            EncryptedEnvelopeCodec.decode(badVersion)
        }

        // Unknown algorithm
        val badAlg = valid.copyOf().apply { this[5] = 0x55 }
        assertFailsWith<MaigStoreTamperedOrCorruptedException> {
            EncryptedEnvelopeCodec.decode(badAlg)
        }

        // Negative key epoch
        val negativeEpoch = valid.copyOf().apply { this[6] = 0x80.toByte() }
        assertFailsWith<MaigStoreTamperedOrCorruptedException> {
            EncryptedEnvelopeCodec.decode(negativeEpoch)
        }
    }

    @Test
    fun `length-prefixed AAD prevents boundary ambiguity between storeName and userAad`() {
        val header = EncryptedEnvelopeCodec.buildHeader(MaigCipherAlgorithm.AES256_GCM, 1L)
        val aad1 = EncryptedEnvelopeCodec.buildAssociatedData(
            header = header,
            storeName = "ab",
            userAad = "c".encodeToByteArray(),
        )
        val aad2 = EncryptedEnvelopeCodec.buildAssociatedData(
            header = header,
            storeName = "a",
            userAad = "bc".encodeToByteArray(),
        )
        assertFalse(aad1.contentEquals(aad2))
    }

    @Test
    fun `wipe zeroes all bytes in buffer`() {
        val secret = byteArrayOf(1, 2, 3, 4, 127, -128)
        secret.wipe()
        assertTrue(secret.all { it == 0.toByte() })
    }
}

class SecurityConfigTest {

    @Test
    fun `validates storeName constraints`() {
        assertFailsWith<IllegalArgumentException> { MaigSecurityConfig(storeName = "") }
        assertFailsWith<IllegalArgumentException> { MaigSecurityConfig(storeName = "   ") }
        assertFailsWith<IllegalArgumentException> { MaigSecurityConfig(storeName = "../escape") }
        assertFailsWith<IllegalArgumentException> { MaigSecurityConfig(storeName = "a/b") }
        assertFailsWith<IllegalArgumentException> { MaigSecurityConfig(storeName = "a b") }
        assertFailsWith<IllegalArgumentException> { MaigSecurityConfig(storeName = "x".repeat(129)) }

        val valid = MaigSecurityConfig(storeName = "auth_tokens-v1.prod")
        assertEquals("auth_tokens-v1.prod", valid.storeName)
    }

    @Test
    fun `validates rotation and auth config bounds`() {
        assertFailsWith<IllegalArgumentException> {
            MaigKeyRotationPolicy.Automatic(maxKeyAge = 0.seconds)
        }
        assertFailsWith<IllegalArgumentException> {
            MaigKeyRotationPolicy.Automatic(maxWritesBeforeRotation = 0L)
        }
        assertFailsWith<IllegalArgumentException> {
            MaigKeyRotationPolicy.Automatic(maxRetainedKeys = 1)
        }
        assertFailsWith<IllegalArgumentException> {
            MaigUserAuthConfig(authValidityDurationSeconds = 0)
        }
        assertFailsWith<IllegalArgumentException> {
            MaigUserAuthConfig(authValidityDurationSeconds = -1)
        }
        assertFailsWith<IllegalArgumentException> {
            MaigSecurityConfig(
                storeName = "invalid_combo",
                recoveryPolicy = MaigKeystoreRecoveryPolicy.EXPLICIT_SOFTWARE_FALLBACK,
                userAuthConfig = MaigUserAuthConfig(authValidityDurationSeconds = 30),
            )
        }

        val okPolicy = MaigKeyRotationPolicy.Automatic(
            maxKeyAge = 1.days,
            maxWritesBeforeRotation = 1L,
            maxRetainedKeys = 2,
        )
        assertEquals(2, okPolicy.maxRetainedKeys)

        val c1 = MaigSecurityConfig(storeName = "eq_test", associatedDataProvider = { byteArrayOf(1) })
        val c2 = MaigSecurityConfig(storeName = "eq_test", associatedDataProvider = { byteArrayOf(2) })
        assertEquals(c1, c2)
        assertEquals(c1.hashCode(), c2.hashCode())
    }
}
