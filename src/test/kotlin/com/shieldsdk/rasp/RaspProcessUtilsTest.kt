package com.shieldsdk.rasp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Local JVM unit test — no Android framework or device needed. `Process`/
 * `Runtime.exec` are plain `java.lang` facilities that work identically on
 * the local JVM this test runs on (only `android.os.Build.VERSION.SDK_INT`
 * is Android-specific inside [RaspProcessUtils], and it resolves to `0` in
 * this environment — which exercises the watcher-thread fallback path
 * exactly like a real device below API 26 would).
 *
 * Uses real, unmocked process execution throughout — matching this repo's
 * existing convention of testing I/O helpers against reality rather than a
 * mock. The host running these tests is assumed to be Windows (this repo's
 * development environment); commands are chosen accordingly.
 */
class RaspProcessUtilsTest {

    @Test
    fun firstLineOf_returnsOutput_forARealCommand() {
        val line = RaspProcessUtils.firstLineOf(arrayOf("cmd", "/c", "echo hello"))
        assertEquals("hello", line?.trim())
    }

    @Test
    fun firstLineOf_returnsNull_forANonExistentCommand() {
        val line = RaspProcessUtils.firstLineOf(
            arrayOf("this_command_should_not_exist_anywhere_12345")
        )
        assertNull(line)
    }

    @Test
    fun firstLineOf_respectsTimeout_forAHangingCommand() {
        // `timeout /t 30` blocks for 30s — the bounded wait must return well
        // before that, proving a hung/wedged shell can never hang the caller.
        val started = System.currentTimeMillis()
        val line = RaspProcessUtils.firstLineOf(
            arrayOf("cmd", "/c", "timeout /t 30 /nobreak"),
            timeoutMs = 500,
        )
        val elapsed = System.currentTimeMillis() - started
        assertNull("a timed-out process must report no output, not partial output", line)
        assertTrue(
            "firstLineOf took ${elapsed}ms but should have returned near the 500ms bound",
            elapsed < 5000,
        )
    }

    @Test
    fun firstLineOf_neverThrows_onMalformedInput() {
        // Empty command array — must resolve to null, never propagate an
        // exception across this helper's boundary.
        val line = RaspProcessUtils.firstLineOf(arrayOf())
        assertNull(line)
    }
}
