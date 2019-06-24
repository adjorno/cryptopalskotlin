package set3

import com.sun.org.apache.xml.internal.security.utils.Base64
import util.AES
import util.CTR
import util.search
import util.xor
import java.io.File
import java.nio.file.Paths
import kotlin.random.Random

/**
 * Break fixed-nonce CTR statistically
 * In this file find a similar set of Base64'd plaintext. Do with them exactly what you did with the first, but solve
 * the problem differently.
 *
 * Instead of making spot guesses at to known plaintext, treat the collection of ciphertexts the same way you would
 * repeating-key XOR.
 *
 * Obviously, CTR encryption appears different from repeated-key XOR, but with a fixed nonce they are effectively the
 * same thing.
 *
 * To exploit this: take your collection of ciphertexts and truncate them to a common length (the length of the smallest
 * ciphertext will work).
 *
 * Solve the resulting concatenation of ciphertexts as if for repeating- key XOR, with a key size of the length of the
 * ciphertext you XOR'd.
 */

private const val BLOCK_SIZE = 16

fun main() {
    val cipher = AES.encryptECB(Random.nextBytes(BLOCK_SIZE))
    val encrypted = File("${Paths.get("").toAbsolutePath()}${File.separator}data${File.separator}20.txt").readLines()
        .map { CTR.encrypt(cipher, 0, Base64.decode(it)) }.toTypedArray()

    // 1. Transpose encrypted to have bytes with the same index in the array
    var index = 0
    val key = generateSequence {
        encrypted.mapNotNull { line -> line.getOrNull(index) }.toByteArray()
            .takeIf { it.isNotEmpty() }.also { index++ }
    }
        // 2. Find the each byte of the key with character frequency attack
        .map { indexedChars -> search(indexedChars).first() }
        .map { result -> result.first.second.toByte() }.toList().toByteArray()

    // 3. XOR the key with each line to decrypt it (some correction might needed)
    encrypted.map {
        (it xor key)
            .also { result -> println(String(result)) }
    }

}