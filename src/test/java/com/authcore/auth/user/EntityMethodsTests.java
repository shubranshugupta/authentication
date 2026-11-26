package com.authcore.auth.user;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/**
 * C6: with Lombok's @Data, toString() printed the password hash, and equals() compared
 * every field. (User and RefreshToken also pointed at each other, which recursed until
 * StackOverflowError; since A4 and C2 the token tables only hold ids.)
 */
class EntityMethodsTests {
    private static final String PASSWORD_HASH = "$2a$10$secret-bcrypt-hash";

    @Test
    void aUserCanBePrintedWithoutTheirPasswordHash() {
        assertThat(user(1).toString()).contains("jane@example.com").doesNotContain(PASSWORD_HASH);
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
}
