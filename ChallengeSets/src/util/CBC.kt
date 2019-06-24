package util

import javax.crypto.Cipher

object CBC {

    fun encrypt(decrypted: ByteArray, ecb: Cipher, iv: ByteArray): ByteArray {
        var stepIV = iv
        return decrypted.asSequence().chunked(ecb.blockSize).map { chunk ->
            ecb.doFinal(chunk.toByteArray() xor stepIV)
                .also { result -> stepIV = result }
        }.reduce { acc, bytes -> acc + bytes }
    }

    fun decrypt(encrypted: ByteArray, ecb: Cipher, iv: ByteArray): ByteArray {
        var stepIV = iv
        return encrypted.asSequence().chunked(ecb.blockSize).map {
            val chunk = it.toByteArray()
            (ecb.doFinal(chunk) xor stepIV).also {
                stepIV = chunk
            }
        }.reduce { acc, bytes -> acc + bytes }
    }

}