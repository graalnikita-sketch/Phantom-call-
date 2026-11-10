package app.phantomcall.protocol

import java.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Test

/** Vectors shared with server/internal/auth/auth_test.go. */
class ProtocolMessagesTest {
    private val spki = Base64.getDecoder().decode(
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEa9d7Fg2qU0XKO0bqV8t0v1cF0rA0Yx2m1sQy2t7lW8b4v6dA3Q1s0qkq2b7j3bq0g6q2z9m1v4yQ1b0v3c5n9g=="
    )

    @Test
    fun registerMessageMatchesServer() {
        assertEquals(
            "PHANTOM-CALL/v1/register\nbm9uY2U\n95065dc48bb6ee14034b8add4956460f7750e0db3f9152ead9edbd0be4857133",
            String(ProtocolMessages.register("bm9uY2U", spki), Charsets.UTF_8)
        )
    }

    @Test
    fun loginMessageMatchesServer() {
        assertEquals(
            "PHANTOM-CALL/v1/login\nbm9uY2U\n00112233445566778899aabbccddeeff",
            String(ProtocolMessages.login("bm9uY2U", "00112233445566778899aabbccddeeff"), Charsets.UTF_8)
        )
    }

    @Test
    fun fingerprintIsGroupedUppercaseHex() {
        assertEquals("9506 5DC4 8BB6 EE14 034B 8ADD 4956 460F", ProtocolMessages.fingerprint(spki))
    }
}
