package set2

import util.AES
import util.CBC
import util.hasEqualBlocks
import util.toHexString
import kotlin.random.Random

/**
 * An ECB/CBC detection oracle
 *
 * Now that you have ECB and CBC working:
 * Write a function to generate a random AES key; that's just 16 random bytes.
 * Write a function that encrypts data under an unknown key --- that is, a function that generates a random key and
 * encrypts under it. The function should look like:
 * encryption_oracle(your-input) => [MEANINGLESS JIBBER JABBER]
 * Under the hood, have the function append 5-10 bytes (count chosen randomly) before the plaintext and 5-10 bytes
 * after the plaintext. Now, have the function choose to encrypt under ECB 1/2 the time, and under CBC the other half
 * (just use random IVs each time for CBC). Use rand(2) to decide which to use. Detect the block cipher mode the
 * function is using each time. You should end up with a piece of code that, pointed at a block box that might be
 * encrypting ECB or CBC, tells you which one is happening.
 */
@ExperimentalUnsignedTypes
fun main() {
    fun printOption(who: String, option: Boolean) {
        println("$who *** ${if (option) "ECB" else "CBC"} ***")
    }

    val oracleOption = Random.nextInt(2) > 0
    printOption("Oracle", oracleOption)
    val detectorOption = detectECB { key: ByteArray, original: ByteArray -> encryptOracle(key, original, oracleOption) }
    printOption("Detector", detectorOption)
}

@ExperimentalUnsignedTypes
fun detectECB(oracle: (key: ByteArray, original: ByteArray) -> ByteArray): Boolean {
    val blockSize = 16
    val key = Random.nextBytes(blockSize)
    // 3 blocks of the same text will give at least 2 equal block after adding random bytes
    val original = "a".repeat(3 * blockSize).toByteArray()

    val encrypted = oracle(key, original)
    println(encrypted.toHexString())

    return encrypted.hasEqualBlocks(blockSize)
}

fun encryptOracle(key: ByteArray, original: ByteArray, ecb: Boolean): ByteArray {
    val updateOriginal = sequence {
        val prefix = Random.nextInt(5, 10)
        yieldAll(Random.nextBytes(prefix).asSequence())
        yieldAll(original.asSequence())
        val suffix = Random.nextInt(5, 10)
        yieldAll(Random.nextBytes(suffix).asSequence())
        ((prefix + original.size + suffix) % key.size).let {
            if (it > 0) {
                repeat(key.size - it) { yield(0.toByte()) }
            }
        }
    }

    val cipher = AES.encryptECB(key)

    return updateOriginal.toList().toByteArray().let {
        if (ecb) {
            cipher.doFinal(it)
        } else {
            CBC.encrypt(it, cipher, Random.nextBytes(key.size))
        }
    }
}