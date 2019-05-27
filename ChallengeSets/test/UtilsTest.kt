package util

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

@ExperimentalUnsignedTypes
class UtilsTest {

    @Test
    fun `test convert hex to base64`() {
        assertEquals(
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
            "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d".hexToBase64()
        )
    }

    @Test
    fun `fixed XOR`() {
        assertEquals(
            "746865206b696420646f6e277420706c6179",
            "1c0111001f010100061a024b53535009181c".xor("686974207468652062756c6c277320657965")
        )
    }

    @Test
    fun `Implement repeating-key XOR`() {
        assertEquals(
            "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272" +
                    "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f",
            """Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal""".xorKey("ICE")
        )
    }

    @Test
    fun `test Hamming weight`() {
        assertEquals(37, "this is a test".hammingWeight("wokka wokka!!!"))
    }

    @Test
    fun `test transposed`() {
        val bytes = arrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9).map { it.toByte() }.toByteArray()
        val transposed = bytes.transposed(3)
        assertArrayEquals(arrayOf(0, 3, 6, 9).map { it.toByte() }.toByteArray(), transposed[0].toByteArray())
        assertArrayEquals(arrayOf(1, 4, 7).map { it.toByte() }.toByteArray(), transposed[1].toByteArray())
        assertArrayEquals(arrayOf(2, 5, 8).map { it.toByte() }.toByteArray(), transposed[2].toByteArray())
    }

    @Test
    fun `test PKCS#7 padding`() {
        assertEquals(
            "YELLOW SUBMARINE${'\u0004'}${'\u0004'}${'\u0004'}${'\u0004'}",
            "YELLOW SUBMARINE".padPKS7(20)
        )
    }

    @Test
    fun `test strip PKCS#7 padding1`() {
        assertEquals("ICE ICE BABY", "ICE ICE BABY\u0004\u0004\u0004\u0004".stripPadPKS7())
    }

    @Test(expected = IllegalArgumentException::class)
    fun `test strip PKCS#7 padding2`() {
        assertEquals("ICE ICE BABY", "ICE ICE BABY\u0005\u0005\u0005\u0005".stripPadPKS7())
    }

    @Test(expected = IllegalArgumentException::class)
    fun `test strip PKCS#7 padding3`() {
        assertEquals("ICE ICE BABY", "ICE ICE BABY\u0001\u0002\u0003\u0004".stripPadPKS7())
    }


}