package set1

import util.hexToByteArray
import java.io.File
import java.nio.file.Paths

/**
 * Detect AES in ECB mode
 *
 * In the file "data/8.txt" are a bunch of hex-encoded ciphertexts.
 * One of them has been encrypted with ECB.
 * Detect it.
 * Remember that the problem with ECB is that it is stateless and deterministic; the same 16 byte plaintext block will always produce the same 16 byte ciphertext.
 */

@ExperimentalUnsignedTypes
fun main() {
    val lines = File("${Paths.get("").toAbsolutePath()}${File.separator}data${File.separator}8.txt").readLines()
    val blockSize = 16
    val result = lines.mapIndexed { index: Int, s: String ->
        index to (s.hexToByteArray().toList().chunked(blockSize).groupBy { it }.map { it.value.size }.max() ?: 0)
    }.maxBy { it.second }

    result?.let { println("""Line ${it.first + 1} has ${it.second} block repetitions. It's probably encrypted with ECB.""") }

}