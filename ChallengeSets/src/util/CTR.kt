package util

import java.math.BigInteger
import javax.crypto.Cipher

object CTR {

    fun encrypt(cipher: Cipher, nonce: ByteArray, decrypted: ByteArray): ByteArray {
        return decrypted.asSequence().chunked(cipher.blockSize).mapIndexed { blockCount, decryptedBlock ->
            val keyBlock = (nonce + BigInteger.valueOf(blockCount.toLong())
                .toByteArray().copyInto(ByteArray(cipher.blockSize / 2) { 0 }))
            decryptedBlock.toByteArray() xor cipher.doFinal(keyBlock)
        }.reduce { acc, bytes -> acc + bytes }
    }

    fun decrypt(cipher: Cipher, nonce: ByteArray, encrypted: ByteArray) = encrypt(cipher, nonce, encrypted)

}