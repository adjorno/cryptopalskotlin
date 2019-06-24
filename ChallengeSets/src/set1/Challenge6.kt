package set1

import util.normalizedDistance
import util.search
import util.transposed
import util.xor
import java.io.File
import java.nio.file.Paths
import java.util.*

/**
 * Break repeating-key XOR
 *
 * There's a file "data/6.txt". It's been base64'd after being encrypted with repeating-key XOR.
 *
 * Decrypt it. Here's how:
 *
 * Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.
 * Write a function to compute the edit distance/Hamming distance between two strings. The Hamming distance is just the
 * number of differing bits. The distance between: "this is a test" and "wokka wokka!!!" is 37.
 * Make sure your code agrees before you proceed.
 *
 * For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes, and find the edit
 * distance between them. Normalize this result by dividing by KEYSIZE.
 *
 * The KEYSIZE with the smallest normalized edit distance is probably the key.
 * You could proceed perhaps with the smallest 2-3 KEYSIZE values. Or take 4 KEYSIZE blocks instead of 2 and average
 * the distances. Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length.
 *
 * Now transpose the blocks: make a block that is the first byte of every block, and a block that is the second byte of
 * every block, and so on.
 *
 * Solve each block as if it was single-character XOR. You already have code to do this.
 *
 * For each block, the single-byte XOR key that produces the best looking histogram is the repeating-key XOR
 * key byte for that block. Put them together and you have the key.
 *
 * This code is going to turn out to be surprisingly useful later on. Breaking repeating-key XOR ("Vigenere")
 * statistically is obviously an academic exercise, a "Crypto 101" thing. But more people "know how" to break it
 * than can actually break it, and a similar technique breaks something much more important.
 */

fun main() {
    val bytes = File("${Paths.get("").toAbsolutePath()}${File.separator}data${File.separator}6.txt").readLines()
        .joinToString(separator = "").let { Base64.getDecoder().decode(it) }
    val key = searchForKey(bytes)

    println(
        """Decrypted text
${String(bytes xor key.toByteArray())}"""
    )
}

fun searchForKey(bytes: ByteArray): String {
    val potentialKeySizes =
        (2..40).map { keySize ->
            val blocks = bytes.size / (keySize * 2)
            keySize to ((0 until blocks).sumByDouble { n -> bytes.normalizedDistance(keySize, n) }) / blocks
        }
            .sortedBy { it.second }.take(10)
            .also { println(it) }
            .map { it.first }


    val keySize = potentialKeySizes[0]

    val key = bytes.transposed(keySize).map { search(it.toByteArray()).first().first.second }
        .joinToString(separator = "").also { println("key = $it") }
    return key
}