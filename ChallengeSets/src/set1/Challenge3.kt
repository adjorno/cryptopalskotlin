package set1

import util.search
import util.toHexString

/**
 * Single-byte XOR cipher
 *
 * The hex encoded string:
 *
 * 1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
 * ... has been XOR'd against a single character. Find the key, decrypt the message.
 *
 * You can do this by hand. But don't: write code to do it for you.
 *
 * How? Devise some method for "scoring" a piece of English plaintext. Character frequency is a good metric.
 * Evaluate each output and choose the one with the best score.
 */

@ExperimentalUnsignedTypes
fun main() {
    printResult(search("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736").first())
}

@ExperimentalUnsignedTypes
fun printResult(result: Pair<Pair<ByteArray, Char>, String>) =
    println("""'${result.first.second}' xor ${result.first.first.toHexString().crop(10)} -> ${result.second}""")

fun String.crop(size: Int) = if (length <= size) this else "${this.substring(0, size - 4)}..."