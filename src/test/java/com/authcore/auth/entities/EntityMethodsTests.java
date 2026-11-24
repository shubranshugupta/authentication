package com.authcore.auth.entities;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;

import org.junit.jupiter.api.Test;

/**
 * C6: User and RefreshToken point at each other. With Lombok's @Data, toString(),
 * equals() and hashCode() followed that link forever (StackOverflowError), and
 * toString() printed the password hash and the refresh token.
 */
class EntityMethodsTests {
    private static final String PASSWORD_HASH = "$2a$10$secret-bcrypt-hash";
    private static final String TOKEN_VALUE = "secret-refresh-token-value";

    @Test
    void linkedUserAndRefreshTokenCanBePrintedAndHashed() {
        User user = linkedUser(1);
        RefreshToken token = user.getRefreshToken();

        assertThat(user.toString()).contains("jane@example.com");
        assertThat(token.toString()).contains("RefreshToken");
        assertThat(user.hashCode()).isEqualTo(user.hashCode());
        assertThat(token.hashCode()).isEqualTo(token.hashCode());
    }

    @Test
    void toStringLeavesOutSecrets() {
        User user = linkedUser(1);

        assertThat(user.toString()).doesNotContain(PASSWORD_HASH).doesNotContain(TOKEN_VALUE);
        assertThat(user.getRefreshToken().toString()).doesNotContain(TOKEN_VALUE).doesNotContain(PASSWORD_HASH);
    }

    @Test
    void entitiesAreEqualWhenTheyHaveTheSameDatabaseId() {
        User user = linkedUser(1);
        User sameRowLoadedAgain = linkedUser(1);
        sameRowLoadedAgain.setFirstName("changed");

        assertThat(user).isEqualTo(sameRowLoadedAgain).hasSameHashCodeAs(sameRowLoadedAgain);
        assertThat(user).isNotEqualTo(linkedUser(2));
    }

    @Test
    void unsavedEntitiesAreOnlyEqualToThemselves() {
        User unsaved = User.builder().email("a@example.com").build();
        User otherUnsaved = User.builder().email("a@example.com").build();

        assertThat(unsaved).isEqualTo(unsaved).isNotEqualTo(otherUnsaved);
    }

    private static User linkedUser(int id) {
        User user = User.builder()
                .id(id)
                .firstName("jane")
                .email("jane@example.com")
                .password(PASSWORD_HASH)
                .role(Role.USER)
                .build();
        RefreshToken token = RefreshToken.builder()
                .id(id)
                .refreshToken(TOKEN_VALUE)
                .expiryDate(Instant.parse("2030-01-01T00:00:00Z"))
                .user(user)
                .build();
        user.setRefreshToken(token);
        return user;
    }
}
