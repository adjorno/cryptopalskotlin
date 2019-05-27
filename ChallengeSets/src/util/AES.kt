package util

import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

object AES {
    fun decryptECB(key: ByteArray, padding: String = "NoPadding") = Cipher.getInstance("AES/ECB/$padding").apply {
        val keySpec = SecretKeySpec(key, "AES")
        init(Cipher.DECRYPT_MODE, keySpec)
    }

    fun encryptECB(key: ByteArray, padding: String = "NoPadding") = Cipher.getInstance("AES/ECB/$padding").apply {
        val keySpec = SecretKeySpec(key, "AES")
        init(Cipher.ENCRYPT_MODE, keySpec)
    }

    fun decryptCBC(key: ByteArray, iv: ByteArray) = Cipher.getInstance("AES/CBC/PKCS5Padding").apply {
        val keySpec = SecretKeySpec(key, "AES")
        init(Cipher.DECRYPT_MODE, keySpec, IvParameterSpec(iv))
    }

    fun encryptCBC(key: ByteArray, iv: ByteArray) = Cipher.getInstance("AES/CBC/PKCS5Padding").apply {
        val keySpec = SecretKeySpec(key, "AES")
        init(Cipher.ENCRYPT_MODE, keySpec, IvParameterSpec(iv))
    }

}
