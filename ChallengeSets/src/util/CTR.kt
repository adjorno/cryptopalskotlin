package util

import java.math.BigInteger
import javax.crypto.Cipher

object CTR {

    fun encrypt(cipher: Cipher, nonce: Long, decrypted: ByteArray): ByteArray {
        return decrypted.asSequence().chunked(cipher.blockSize).mapIndexed { blockCount, decryptedBlock ->
            val halfBlock = cipher.blockSize / 2
            val keyBlock = padValue(nonce, halfBlock) + padValue(blockCount.toLong(), halfBlock)
            decryptedBlock.toByteArray() xor cipher.doFinal(keyBlock)
        }.reduce { acc, bytes -> acc + bytes }
    }

    fun decrypt(cipher: Cipher, nonce: Long, encrypted: ByteArray) = encrypt(cipher, nonce, encrypted)

    private fun padValue(value: Long, blockSize: Int) =
        BigInteger.valueOf(value).toByteArray().copyInto(ByteArray(blockSize) { 0 })
}