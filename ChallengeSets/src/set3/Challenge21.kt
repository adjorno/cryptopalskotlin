package set3

/**
 * Implement the MT19937 Mersenne Twister RNG
 * You can get the psuedocode for this from Wikipedia.
 *
 * If you're writing in Python, Ruby, or (gah) PHP, your language is probably already giving you MT19937 as "rand()";
 * don't use rand(). Write the RNG yourself.
 */
fun main() {
    val prg = MT19937().apply { seed(5489) }
    repeat(1000) {
        println(prg.next())
    }
}

/**
 * https://en.wikipedia.org/wiki/Mersenne_Twister
 */
class MT19937() {

    companion object {
        private const val w = 32
        private const val n = 624
        private const val m = 397
        private const val r = 31

        private const val a = 0x9908B0DF

        private const val u = 11
        private const val d = 0xFFFFFFFF

        private const val s = 7
        private const val b = 0x9D2C5680

        private const val t = 15
        private const val c = 0xEFC60000

        private const val l = 18

        private const val f = 0x6C078965

        private const val lower_mask = ((1 shl r).toLong() - 1) and d
        private const val upper_mask = lower_mask xor d
    }

    private var index = 0
    private var MT = LongArray(n)

    fun seed(seed: Long) {
        MT[0] = seed and 0xffffffff
        (1 until MT.size).forEach { i ->
            MT[i] = ((f * (MT[i - 1] xor (MT[i - 1] shr (w - 2)))) + i) and d
        }
        index = n
    }

    fun next(): Long {
        if (index == n) {
            generate()
        }
        var y = MT[index]
        y = y xor ((y shr u) and d)
        y = y xor ((y shl s) and b)
        y = y xor ((y shl t) and c)
        y = y xor (y shr l)

        index++
        return y and d
    }

    private fun generate() {
        (0 until MT.size).forEach { i ->
            val y = (MT[i] and upper_mask) + (MT[(i + 1) % n] and lower_mask)
            MT[i] = MT[(i + m) % n] xor (y shr 1)
            if ((y % 2).toInt() != 0) {
                MT[i] = MT[i] xor a
            }
        }
        index = 0
    }
}