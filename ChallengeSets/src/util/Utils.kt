package util

import java.util.*
import kotlin.experimental.xor

@ExperimentalUnsignedTypes
fun String.hexToByteArray() = generateSequence(0) { index -> if (index + 2 >= length) null else index + 2 }
    .map { index -> substring(index, index + 2).toUByte(16).toByte() }.toList().toByteArray()

@ExperimentalUnsignedTypes
fun String.hexToBase64(): String = hexToByteArray().let { Base64.getEncoder().encodeToString(it) }

@ExperimentalUnsignedTypes
fun String.xor(against: String) = hexToByteArray().xor(against.hexToByteArray()).toHexString()

val character_frequencies = mapOf(
    'a' to .08167, 'b' to .01492, 'c' to .02782, 'd' to .04253,
    'e' to .12702, 'f' to .02228, 'g' to .02015, 'h' to .06094,
    'i' to .06094, 'j' to .00153, 'k' to .00772, 'l' to .04025,
    'm' to .02406, 'n' to .06749, 'o' to .07507, 'p' to .01929,
    'q' to .00095, 'r' to .05987, 's' to .06327, 't' to .09056,
    'u' to .02758, 'v' to .00978, 'w' to .02360, 'x' to .00150,
    'y' to .01974, 'z' to .00074, ' ' to .13000
)

fun String.etaoinshrdlu() = sumByDouble { c -> character_frequencies.getOrDefault(c, 0.toDouble()) }

@ExperimentalUnsignedTypes
fun search(string: String) = search(arrayOf(string))

@ExperimentalUnsignedTypes
fun search(strings: Array<String>) = search(strings.map { it.hexToByteArray() }.toTypedArray())

fun search(bytes: ByteArray) = search(arrayOf(bytes))

fun search(strings: Array<ByteArray>) =
    strings.flatMap { data ->
        (0..255).map { it.toChar() }.map { c -> (data to c) to String(data.xor(c.toByte())) }
    }.sortedByDescending { it.second.etaoinshrdlu() }

fun String.hammingWeight(against: String) = toByteArray().hammingWeight(against.toByteArray())

fun <T> Sequence<T>.repeat(n: Int) = sequence { repeat(n) { yieldAll(this@repeat) } }

/**
 * Expand [against] array by repeating its value
 */
fun ByteArray.xor(against: ByteArray) =
    zip(against.asSequence().repeat(size).toList().toByteArray()).map { it.first xor it.second }.toByteArray()

/**
 * Expand [against] byte by repeating its value
 */
fun ByteArray.xor(against: Byte) = this.xor(arrayOf(against).toByteArray())

@ExperimentalUnsignedTypes
fun String.xorKey(key: String) = toByteArray().xor(key.toByteArray()).toHexString()

/**
 * Does not expand [against]
 */
fun ByteArray.xorOnce(against: ByteArray) =
    (0 until maxOf(size, against.size))
        .map { if (it >= size) against[it] else if (it >= against.size) this[it] else this[it] xor against[it] }.toByteArray()

@ExperimentalUnsignedTypes
fun ByteArray.toHexString() = joinToString(separator = "") { it.toUByte().toString(16).padStart(2, '0') }

fun ByteArray.hammingWeight(against: ByteArray) = zip(against).sumBy {
    (it.first xor it.second).toInt().toBigInteger().bitCount()
}

fun ByteArray.normalizedDistance(blockSize: Int, blockIndex: Int) =
    sliceArray(blockSize * 2 * blockIndex until blockSize * (2 * blockIndex + 1))
        .hammingWeight(sliceArray(blockSize * (2 * blockIndex + 1) until blockSize * (2 * blockIndex + 2)))
        .toDouble() / blockSize

fun ByteArray.transposed(keySize: Int): List<MutableList<Byte>> {
    val transposed = arrayOfNulls<MutableList<Byte>>(keySize)
    forEachIndexed { index, byte ->
        transposed[index % keySize] = (transposed[index % keySize] ?: mutableListOf()).also { it += byte }
    }
    return transposed.filterNotNull()
}

@ExperimentalUnsignedTypes
fun ByteArray.padPKS7(blockSize: Int) = (blockSize - (this.size % blockSize)).toByte().let { padValue ->
    this + ByteArray(padValue.toInt()) { padValue }
}

@ExperimentalUnsignedTypes
fun String.padPKS7(blockSize: Int) = String(this.toByteArray().padPKS7(blockSize))

@Throws(IllegalArgumentException::class)
fun ByteArray.stripPadPKS7(): ByteArray {
    val padLength = this[size - 1]
    if (padLength <= 0) throw IllegalArgumentException("String is not PKS7 padded!")
    (1..padLength).forEach { if (this[size - it] != padLength) throw IllegalArgumentException("String is not PKS7 padded!") }
    return this.copyOfRange(0, size - padLength)
}

@Throws(IllegalArgumentException::class)
fun String.stripPadPKS7() = String(toByteArray().stripPadPKS7())

/**
 * Count repeat blocks since ECB gives the same result for the same blocks.
 */
fun ByteArray.hasEqualBlocks(blockSize: Int) =
    asSequence().chunked(blockSize).groupBy { it }.map { it.value.size }.sortedDescending().first() > 1

fun ByteArray.commonPrefixLength(against: ByteArray): Int {
    var i = 0
    while (i < this.size && i < against.size && this[i] == against[i]) {
        i++
    }
    return i
}

fun String.toBlocks(blockSize: Int) =
    chunked(blockSize).joinToString(separator = "   ")