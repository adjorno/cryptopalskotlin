package set1

import util.search
import java.io.File
import java.nio.file.Paths

/**
 * Detect single-character XOR
 *
 * One of the 60-character strings in the file "data/4.txt" has been encrypted by single-character XOR.
 * Find it.
 * (Your code from #3 should help.)
 */
@ExperimentalUnsignedTypes
fun main() {
    val strings = File("${Paths.get("").toAbsolutePath()}${File.separator}data${File.separator}4.txt").readLines()
    val result = search(strings.toTypedArray())
    printResult(result.first())
}
