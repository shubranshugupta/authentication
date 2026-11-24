package com.authcore.auth.token;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Base64;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.authcore.auth.common.AuthConfigProperties;

class TokenHasherTests {
    private final TokenHasher hasher = hasher((byte) 1);

    @Test
    void theSameInputAlwaysHasTheSameHash() {
        assertThat(hasher.hash(TokenPurpose.PASSWORD_RESET, 1, "12345678"))
                .isEqualTo(hasher((byte) 1).hash(TokenPurpose.PASSWORD_RESET, 1, "12345678"))
                .matches("[0-9a-f]{64}");
    }

    @Test
    void everyPartOfTheInputCounts() {
        assertThat(Set.of(
                hasher.hash(TokenPurpose.PASSWORD_RESET, 1, "12345678"),
                hasher.hash(TokenPurpose.PASSWORD_RESET, 1, "12345679"),
                hasher.hash(TokenPurpose.PASSWORD_RESET, 2, "12345678"),
                hasher.hash(TokenPurpose.PASSWORD_RESET, null, "12345678"),
                hasher.hash(TokenPurpose.ACCOUNT_DELETION, 1, "12345678"))).hasSize(5);
    }

    /** Whoever reads the database can't try all the codes without the key. */
    @Test
    void theHashDependsOnTheServersKey() {
        assertThat(hasher.hash(TokenPurpose.PASSWORD_RESET, 1, "12345678"))
                .isNotEqualTo(hasher((byte) 2).hash(TokenPurpose.PASSWORD_RESET, 1, "12345678"));
    }

    private static TokenHasher hasher(byte key) {
        byte[] secret = new byte[32];
        secret[0] = key;
        AuthConfigProperties properties = new AuthConfigProperties();
        properties.getToken().setSecretKey(Base64.getEncoder().encodeToString(secret));
        return new TokenHasher(properties);
    }
}
