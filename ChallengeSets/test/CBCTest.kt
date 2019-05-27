package util

import org.junit.Assert.assertArrayEquals
import org.junit.Test
import java.io.File
import java.nio.file.Paths
import java.util.*

class CBCTest {
    @Test
    fun `Implement CBC mode`() {
        val bytes =
            File("${Paths.get("").toAbsolutePath()}${File.separator}..${File.separator}data${File.separator}10.txt").readLines()
                .joinToString(separator = "").let { Base64.getDecoder().decode(it) }

        val key = "YELLOW SUBMARINE".toByteArray()

        val decrypted = CBC.decrypt(bytes, AES.decryptECB(key), ByteArray(key.size) { 0 })

        val encrypted = CBC.encrypt(decrypted, AES.encryptECB(key), ByteArray(key.size) { 0 })

        assertArrayEquals(bytes, encrypted)
    }
}