package set2

import util.AES
import kotlin.experimental.xor
import kotlin.random.Random

const val blockSize = 16
var iv = Random.nextBytes(blockSize)

/**
 * CBC bitflipping attacks
 * Generate a random AES key.
 *
 * Combine your padding code and CBC code to write two functions.
 *
 * The first function should take an arbitrary input string, prepend the string:
 *
 * "comment1=cooking%20MCs;userdata="
 * .. and append the string:
 *
 * ";comment2=%20like%20a%20pound%20of%20bacon"
 * The function should quote out the ";" and "=" characters.
 *
 * The function should then pad out the input to the 16-byte AES block length and encrypt it under the random AES key.
 *
 * The second function should decrypt the string and look for the characters ";admin=true;" (or, equivalently, decrypt,
 * split the string on ";", convert each resulting string into 2-tuples, and look for the "admin" tuple).
 *
 * Return true or false based on whether the string exists.
 *
 * If you've written the first function properly, it should not be possible to provide user input to it that will
 * generate the string the second function is looking for. We'll have to break the crypto to do that.
 *
 * Instead, modify the ciphertext (without knowledge of the AES key) to accomplish this.
 *
 * You're relying on the fact that in CBC mode, a 1-bit error in a ciphertext block:
 *
 * - Completely scrambles the block the error occurs in
 * - Produces the identical 1-bit error(/edit) in the next ciphertext block.
 */

@ExperimentalUnsignedTypes
fun main() {
    val key = Random.Default.nextBytes(blockSize)
    val encrypted = encrypt(key, "AAAAAAAAAAAAAAAA?admin?true")
    encrypted[2 * blockSize] = encrypted[2 * blockSize] xor '?'.toByte() xor ';'.toByte()
    encrypted[2 * blockSize + 6] = encrypted[2 * blockSize + 6] xor '?'.toByte() xor '='.toByte()
    println(decrypt(key, encrypted))
}

@ExperimentalUnsignedTypes
fun encrypt(key: ByteArray, str: String): ByteArray {
    fun clean(str: String) = str.replace("=", "").replace(";", "")
    val result = "comment1=cooking%20MCs;userdata=${clean(str)};comment2=%20like%20a%20pound%20of%20bacon"
        .also { println(it) }
    return AES.encryptCBC(key, iv).doFinal(result.toByteArray())
}

fun decrypt(key: ByteArray, encrypted: ByteArray): Boolean {
    return String(AES.decryptCBC(key, iv).doFinal(encrypted))
        .also { println(it) }
        .split(";").map { it.split("=").let { tuple -> tuple[0] to tuple[1] } }
        .firstOrNull { tuple -> tuple.first == "admin" } != null
}