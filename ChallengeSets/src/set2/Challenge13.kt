package set2

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.json
import util.AES
import util.padPKS7
import util.stripPadPKS7
import kotlin.random.Random

/**
 * ECB cut-and-paste
 *
 * Write a k=v parsing routine, as if for a structured cookie. The routine should take:
 *
 * foo=bar&baz=qux&zap=zazzle
 * ... and produce:
 *
 * {
 * foo: 'bar',
 * baz: 'qux',
 * zap: 'zazzle'
 * }
 * (you know, the object; I don't care if you convert it to JSON).
 *
 * Now write a function that encodes a user profile in that format, given an email address. You should have something
 * like:
 *
 * profileFor("foo@bar.com")
 * ... and it should produce:
 *
 * {
 * email: 'foo@bar.com',
 * uid: 10,
 * role: 'user'
 * }
 * ... encoded as:
 *
 * email=foo@bar.com&uid=10&role=user
 * Your "profileFor" function should not allow encoding metacharacters (& and =). Eat them, quote them, whatever you
 * want to do, but don't let people set their email address to "foo@bar.com&role=admin".
 *
 * Now, two more easy functions. Generate a random AES key, then:
 *
 * Encrypt the encoded user profile under the key; "provide" that to the "attacker".
 * Decrypt the encoded user profile and parse it.
 * Using only the user input to profileFor() (as an oracle to generate "valid" ciphertexts) and the ciphertexts
 * themselves, make a role=admin profile.
 */
@ExperimentalUnsignedTypes
fun main() {
    val blockSize = 16
    val key = Random.nextBytes(blockSize)

    // 1. Compute the required length of e-mail which would make the length of encoded profile multiplied by block size
    // and expand it for "user" length in order to push the cipher text out to the last block. Direct formula is:
//    val arbitraryEmailLength = blockSize - ("email=&uid=10&role=user".length % blockSize) + "user".length
    var oldSize = 0
    var newSize = 0
    var emailLength = 0
    while (oldSize == 0 || newSize == oldSize) {
        oldSize = newSize
        newSize = encryptProfile(key, "A".repeat(++emailLength)).size
    }
    val arbitraryEmailLength = emailLength + "user".length

    // 2. Get the cipher text for encrypted profile with e-mail of length found in the previous step. If the last block
    // is replaced with the cipher text of "admin" it would give a required result.
    val originalCipherText = encryptProfile(key, "A".repeat(arbitraryEmailLength))
    println("Original profile:")
    println(decryptProfile(key, originalCipherText).toString())

    // 3. Create a cipher text for the email which consists of two parts: content of the first part is not important but
    // only its size, it should be blockSize - "email=".length is order to fill 1st block of cipher text, the second
    // part should be PKCS7 padded "admin" which is "admin\x0011\x0011..."
    val adminEmail = "A".repeat(blockSize - "email=".length) + "admin".padPKS7(blockSize)
    val adminCipherText = encryptProfile(key, adminEmail)

    // 4. Replace last block of original cipher text with 2nd block of admin cipher text to get required result.
    (0 until blockSize).forEach {
        originalCipherText[originalCipherText.size - blockSize + it] = adminCipherText[blockSize + it]
    }
    println("Updated profile:")
    println(decryptProfile(key, originalCipherText).toString())

}

fun parse(original: String): JsonObject = original.split("&").map { param ->
    param.split("=").let { keyValue -> keyValue[0] to keyValue[1] }
}.let { params ->
    return json {
        params.forEach { it.first to it.second }
    }
}

fun encodeProfile(profile: Map<String, String>): String {
    fun clean(str: String) = str.replace("=", "").replace("&", "")
    return profile.map { clean(it.key) + "=" + clean(it.value) }.joinToString(separator = "&")
}

fun profileFor(email: String) = encodeProfile(mapOf("email" to email, "uid" to "10", "role" to "user"))

@ExperimentalUnsignedTypes
fun encryptProfile(key: ByteArray, email: String): ByteArray =
    AES.encryptECB(key).doFinal(profileFor(email).padPKS7(key.size).toByteArray())

@ExperimentalUnsignedTypes
fun decryptProfile(key: ByteArray, encrypted: ByteArray): JsonObject =
    parse(String(AES.decryptECB(key).doFinal(encrypted).stripPadPKS7()))