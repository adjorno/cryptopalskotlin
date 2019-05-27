package set1

import util.AES
import java.io.File
import java.nio.file.Paths
import java.util.*

/**
 * AES in ECB mode
 * The Base64-encoded content in this file has been encrypted via AES-128 in ECB mode under the key
 * "YELLOW SUBMARINE". (case-sensitive, without the quotes; exactly 16 characters; I like "YELLOW SUBMARINE" because
 * it's exactly 16 bytes long, and now you do too).
 *
 * Decrypt it. You know the key, after all.
 *
 * Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher.
 */
fun main() {
    val bytes = File("${Paths.get("").toAbsolutePath()}${File.separator}data${File.separator}7.txt").readLines()
        .joinToString(separator = "").let { Base64.getDecoder().decode(it) }

    println(String(AES.decryptECB("YELLOW SUBMARINE".toByteArray()).doFinal(bytes)))
}