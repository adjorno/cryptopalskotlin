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

    var decrypted = ""
    // Split in blocks and decrypt each block as ECB and then XOR with previous block (or IV in case of 1st block)
    // to get the CBC result
    val blocks = cipher2iv.first.toList().chunked(blockSize) { it.toByteArray() }
    (blocks.size - 1 downTo 0).forEach {
        // Decrypt block as ECB
        val decryptedBlock = decryptBlock(blocks[it], server::decryptAndCheckPadding)
        // XOR it with previous block to get CBC
        val xored = decryptedBlock.zip(if (it > 0) blocks[it - 1] else cipher2iv.second)
            .map { previousAndCurrent -> previousAndCurrent.first xor previousAndCurrent.second }
            .toByteArray()
        decrypted = String(xored) + decrypted
    }

    println("Detector decrypted:")
    println(decrypted.stripPadPKS7())
}

fun decryptBlock(block: ByteArray, oracle: (ByteArray, ByteArray) -> Boolean): ByteArray {
    val decryptedBlock = ByteArray(blockSize)
    // Decrypt the block using bitflipping attack to get the correct value of every possible padding
    ((blockSize - 1) downTo 0).forEach { i ->
        val padding = (blockSize - i).toByte()
        val prefix = Random.nextBytes(i)
        // Try to find i-byte which would give a correct padding
        (Byte.MIN_VALUE..Byte.MAX_VALUE).first {
            // Generated vector is constructed from 3 parts:
            // - random prefix
            // - searching byte
            // - decrypted block xored with expected padding (bitflipping attack to change the result)
            val genVector =
                prefix + byteArrayOf(it.toByte()) + decryptedBlock.takeLast(padding - 1).map { it xor padding }.toByteArray()
            oracle(block, genVector)
        }.also {
            // decrypt i-byte of this block by xoring the found value with padding to flip it back
            decryptedBlock[i] = it.toByte() xor padding
        }
    }
    return decryptedBlock
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
        println("Oracle chose:")
        println(String(Base64.decode(strings[randomStringId])))
    }

    fun encrypt(): Pair<ByteArray, ByteArray> {
        val iv = Random.nextBytes(blockSize)
        val decoded = Base64.decode(strings[randomStringId]).padPKS7(blockSize)
        return CBC.encrypt(decoded, AES.encryptECB(key), iv) to iv
    }

    fun decryptAndCheckPadding(cipher: ByteArray, iv: ByteArray) =
        try {
            CBC.decrypt(cipher, AES.decryptECB(key), iv).stripPadPKS7()
            true
        } catch (e: IllegalArgumentException) {
            false
        } catch (e: BadPaddingException) {
            false
        }
}