package util.set2

import org.junit.Assert.assertEquals
import org.junit.Test
import set2.encodeProfile
import set2.parse
import set2.profileFor

class Challenge13Test {
    @Test
    fun `test parse() function1`() {
        assertEquals(2, parse("baz=qux&zap=zazzle").size)
    }

    @Test
    fun `test parse() function2`() {
        assertEquals(3, parse("foo=bar&baz=qux&zap=zazzle").size)
    }

    @Test
    fun `test encode_profile()`() {
        assertEquals(
            "foo=bar&baz=qux&zap=zazzle",
            encodeProfile(mapOf("foo" to "bar", "baz&" to "qux", "zap" to "zazz=le"))
        )
    }

    @Test
    fun `test profile_for()`() {
        assertEquals("email=foo@bar.com&uid=10&role=user", profileFor("foo@bar.com"))
    }

}