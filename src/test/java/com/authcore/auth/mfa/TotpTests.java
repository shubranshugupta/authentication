package com.authcore.auth.mfa;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.api.Test;

/** The test values of RFC 6238 (appendix B, SHA-1), cut to the 6 digits apps show. */
class TotpTests {
    private static final byte[] SECRET = "12345678901234567890".getBytes(US_ASCII);

    @ParameterizedTest
    @CsvSource({
            "59, 287082",
            "1111111109, 081804",
            "1111111111, 050471",
            "1234567890, 005924",
            "2000000000, 279037",
            "20000000000, 353130" })
    void codesAreThoseOfTheRfc(long epochSecond, String code) {
        assertThat(Totp.code(SECRET, Totp.step(Instant.ofEpochSecond(epochSecond)))).isEqualTo(code);
    }

    @Test
    void aStepIs30Seconds() {
        assertThat(Totp.step(Instant.ofEpochSecond(0))).isZero();
        assertThat(Totp.step(Instant.ofEpochSecond(29))).isZero();
        assertThat(Totp.step(Instant.ofEpochSecond(30))).isEqualTo(1);
    }

    @Test
    void theSecretIsBase32AsAppsTakeIt() {
        // RFC 4648 test vectors, without padding.
        assertThat(Totp.base32(SECRET)).isEqualTo("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        assertThat(Totp.base32("foobar".getBytes(US_ASCII))).isEqualTo("MZXW6YTBOI");
        assertThat(Totp.fromBase32("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")).isEqualTo(SECRET);
        assertThat(Totp.fromBase32("mzxw6ytboi")).isEqualTo("foobar".getBytes(US_ASCII));
    }
}
