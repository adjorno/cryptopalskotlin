package util

import javax.crypto.Cipher

object CBC {

    fun encrypt(decrypted: ByteArray, ecb: Cipher, iv: ByteArray): ByteArray {
        var stepIV = iv
        return sequence {
            yieldAll(decrypted.asSequence())
        }.chunked(ecb.blockSize).map { chunk ->
            ecb.doFinal(chunk.toByteArray().xor(stepIV)).also { result ->
                stepIV = result
            }.toTypedArray()
        }.toList().toTypedArray().flatten().toByteArray()
    }

    fun decrypt(encrypted: ByteArray, ecb: Cipher, iv: ByteArray): ByteArray {
        var stepIV = iv
        return encrypted.asSequence().chunked(ecb.blockSize).map {
            val chunk = it.toByteArray()
            ecb.doFinal(chunk).xor(stepIV).also {
                stepIV = chunk
            }.toTypedArray()
        }.toList().toTypedArray().flatten().toByteArray()
    }

}