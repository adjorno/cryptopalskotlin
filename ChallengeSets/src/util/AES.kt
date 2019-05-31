package util

import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

object AES {
    fun decryptECB(key: ByteArray): Cipher = Cipher.getInstance("AES/ECB/NoPadding").apply {
        val keySpec = SecretKeySpec(key, "AES")
        init(Cipher.DECRYPT_MODE, keySpec)
    }

    fun encryptECB(key: ByteArray): Cipher = Cipher.getInstance("AES/ECB/NoPadding").apply {
        val keySpec = SecretKeySpec(key, "AES")
        init(Cipher.ENCRYPT_MODE, keySpec)
    }

}
