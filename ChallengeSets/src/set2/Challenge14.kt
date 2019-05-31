package set2

import util.AES
import util.commonPrefixLength
import util.padPKS7
import java.util.*
import kotlin.random.Random

/**
 * Byte-at-a-time ECB decryption (Harder)
 * Take your oracle function from #12. Now generate a random count of random bytes and prepend this string to every
 * plaintext. You are now doing:
 *
 * AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)
 * Same goal: decrypt the target-bytes.
 *
 * Stop and think for a second.
 * What's harder than challenge #12 about doing this? How would you overcome that obstacle? The hint is: you're using
 * all the tools you already have; no crazy math is required.
 *
 * Think "STIMULUS" and "RESPONSE".
 */

private const val blockSize = 16

@ExperimentalUnsignedTypes
fun main() {
    val unknown = String(
        Base64.getDecoder().decode(
            "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
                    + "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
                    + "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
                    + "YnkK"
        )
    )
    val random = Random.nextBytes(Random.nextInt(blockSize))
    val cipher = AES.encryptECB(Random.nextBytes(blockSize))
    val oracle = { known: String -> cipher.doFinal((random + (known + unknown).toByteArray()).padPKS7(blockSize)) }

    println(decrypt(oracle))
}

private fun decrypt(oracle: (String) -> ByteArray): String {
    var lastResult = byteArrayOf()
    var newResult = byteArrayOf()
    var missingPrefix = 0
    var blockSize = 0
    while (lastResult.isEmpty() || blockSize <= 1) {
        lastResult = newResult
        newResult = oracle("A".repeat(++missingPrefix))
        blockSize = lastResult.commonPrefixLength(newResult)
    }
    println("Block size is $blockSize")
    missingPrefix = (missingPrefix - 1) % blockSize

    val textSizeWithPadding = oracle("").size
    var cracked = ""
    (0 until textSizeWithPadding).forEach { index ->
        if (index == cracked.length) {
            val known = "A".repeat(blockSize - ((cracked.length + 1) % blockSize) + missingPrefix)
            (0..255).asSequence().map { it.toChar().toString() }.firstOrNull {
                oracle(known + cracked + it).copyOfRange(
                    0,
                    known.length + index + 1 + (blockSize - missingPrefix) % blockSize
                )
                    .contentEquals(
                        oracle(known).copyOfRange(
                            0,
                            known.length + index + 1 + (blockSize - missingPrefix) % blockSize
                        )
                    )
            }?.apply {
                cracked += this
            }
        }
    }
    return cracked
}