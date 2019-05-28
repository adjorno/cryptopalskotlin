package set3

import com.sun.org.apache.xml.internal.security.utils.Base64
import util.AES
import util.CBC
import util.padPKS7
import util.stripPadPKS7
import javax.crypto.BadPaddingException
import kotlin.experimental.xor
import kotlin.random.Random

/**
 * The CBC padding oracle
 * This is the best-known attack on modern block-cipher cryptography.
 *
 * Combine your padding code and your CBC code to write two functions.
 *
 * The first function should select at random one of the following 10 strings:
 *
 * MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
 * MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
 * MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
 * MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
 * MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
 * MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
 * MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
 * MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
 * MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
 * MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93
 * ... generate a random AES key (which it should save for all future encryptions), pad the string out to the 16-byte
 * AES block size and CBC-encrypt it under that key, providing the caller the ciphertext and IV.
 *
 * The second function should consume the ciphertext produced by the first function, decrypt it, check its padding,
 * and return true or false depending on whether the padding is valid.
 *
 * What you're doing here.
 * This pair of functions approximates AES-CBC encryption as its deployed serverside in web applications; the second
 * function models the server's consumption of an encrypted session token, as if it was a cookie.
 *
 * It turns out that it's possible to decrypt the ciphertexts provided by the first function.
 *
 * The decryption here depends on a side-channel leak by the decryption function. The leak is the error message that
 * the padding is valid or not.
 *
 * You can find 100 web pages on how this attack works, so I won't re-explain it. What I'll say is this:
 *
 * The fundamental insight behind this attack is that the byte 01h is valid padding, and occur in 1/256 trials of
 * "randomized" plaintexts produced by decrypting a tampered ciphertext.
 *
 * 02h in isolation is not valid padding.
 *
 * 02h 02h is valid padding, but is much less likely to occur randomly than 01h.
 *
 * 03h 03h 03h is even less likely.
 *
 * So you can assume that if you corrupt a decryption AND it had valid padding, you know what that padding byte is.
 *
 * It is easy to get tripped up on the fact that CBC plaintexts are "padded". Padding oracles have nothing to do with
 * the actual padding on a CBC plaintext. It's an attack that targets a specific bit of code that handles decryption.
 * You can mount a padding oracle on any CBC block, whether it's padded or not.
 */
private const val blockSize = 16

@ExperimentalUnsignedTypes
fun main() {
    val server = Server()
    val cipher2iv = server.encrypt()
    println(decipher(cipher2iv.first, cipher2iv.second, server::decryptAndCheckPadding))
}

fun decipher(cipher: ByteArray, iv: ByteArray, padding_oracle: (cipher: ByteArray, iv: ByteArray) -> Boolean): String {
    var knownP = ""
    val blocks = cipher.size / blockSize
    (blocks downTo 1).forEach {
        val st = cipher.slice(0 until blockSize * it).toByteArray()
        knownP = decipher_last_block(st, iv, padding_oracle) + knownP
    }
    return knownP.stripPadPKS7()
}

fun decipher_last_block(
    st: ByteArray, iv: ByteArray,
    padding_oracle: (iv: ByteArray, cipher: ByteArray) -> Boolean
): String {
    var knownI = byteArrayOf()
    var knownP = byteArrayOf()
    ((blockSize - 1) downTo 0).forEach { i ->
        val k = (blockSize - i).toByte()
        val prefix = Random.nextBytes(i)
        (Byte.MIN_VALUE..Byte.MAX_VALUE).first {
            val c1 =
                if (st.size > blockSize) st.slice((st.size - blockSize * 2) until (st.size - blockSize)).toByteArray() else iv
            val c1p = prefix + byteArrayOf(it.toByte()) + knownI.map { ch -> ch xor k }.toByteArray()
            val sp =
                st.slice(0 until (st.size - blockSize * 2)).toByteArray() + c1p + st.slice((st.size - blockSize) until st.size).toByteArray()
            var result = false
            if (padding_oracle(sp, iv)) {
                val iPrev = it.toByte() xor k
                val pPrev = c1[c1.size - k] xor iPrev
                knownI = byteArrayOf(iPrev) + knownI
                knownP = byteArrayOf(pPrev) + knownP
                result = true
            }
            result
        }
    }
    return String(knownP)
}

@ExperimentalUnsignedTypes
class Server {
    companion object {
        val strings = arrayOf(
            "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
            "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
            "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
            "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
            "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
            "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
            "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
            "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
            "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
            "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
        )
    }

    private val key = Random.nextBytes(blockSize)
    private val randomStringId = Random.nextInt(strings.size)

    init {
        println(String(Base64.decode(strings[randomStringId])))
    }

    fun encrypt(): Pair<ByteArray, ByteArray> {
        val iv = Random.nextBytes(blockSize)
        val decoded = Base64.decode(strings[randomStringId])
        return AES.encryptCBC(key, iv).doFinal(decoded) to iv
    }

    fun decryptAndCheckPadding(cipher: ByteArray, iv: ByteArray) =
        try {
            CBC.decrypt(cipher, AES.decryptECB(key), iv)
            //AES.decryptCBC(key, iv).doFinal(cipher)
                .stripPadPKS7()
            true
        } catch (e: IllegalArgumentException) {
            false
        } catch (e: BadPaddingException) {
            false
        }
}