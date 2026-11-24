package com.authcore.auth.entities;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;

import org.junit.jupiter.api.Test;

/**
 * C6: with Lombok's @Data, toString() printed the password hash and the refresh token,
 * and equals() compared every field. (User and RefreshToken also pointed at each other,
 * which recursed until StackOverflowError; since A4 only the token points at the user.)
 */
class EntityMethodsTests {
    private static final String PASSWORD_HASH = "$2a$10$secret-bcrypt-hash";
    private static final String TOKEN_VALUE = "secret-refresh-token-value";

    @Test
    void userAndRefreshTokenCanBePrintedAndHashed() {
        User user = user(1);
        RefreshToken token = refreshToken(1, user);

        assertThat(user.toString()).contains("jane@example.com");
        assertThat(token.toString()).contains("RefreshToken");
        assertThat(user.hashCode()).isEqualTo(user.hashCode());
        assertThat(token.hashCode()).isEqualTo(token.hashCode());
    }

    @Test
    void toStringLeavesOutSecrets() {
        User user = user(1);

        assertThat(user.toString()).doesNotContain(PASSWORD_HASH);
        assertThat(refreshToken(1, user).toString()).doesNotContain(TOKEN_VALUE).doesNotContain(PASSWORD_HASH);
    }

    @Test
    void entitiesAreEqualWhenTheyHaveTheSameDatabaseId() {
        User user = user(1);
        User sameRowLoadedAgain = user(1);
        sameRowLoadedAgain.setFirstName("changed");

        assertThat(user).isEqualTo(sameRowLoadedAgain).hasSameHashCodeAs(sameRowLoadedAgain);
        assertThat(user).isNotEqualTo(user(2));
    }

    @Test
    void unsavedEntitiesAreOnlyEqualToThemselves() {
        User unsaved = User.builder().email("a@example.com").build();
        User otherUnsaved = User.builder().email("a@example.com").build();

        assertThat(unsaved).isEqualTo(unsaved).isNotEqualTo(otherUnsaved);
    }

    private static User user(int id) {
        return User.builder()
                .id(id)
                .firstName("jane")
                .email("jane@example.com")
                .password(PASSWORD_HASH)
                .role(Role.USER)
                .build();
    }

    private static RefreshToken refreshToken(int id, User user) {
        return RefreshToken.builder()
                .id(id)
                .refreshToken(TOKEN_VALUE)
                .expiryDate(Instant.parse("2030-01-01T00:00:00Z"))
                .user(user)
                .build();
    }
}
