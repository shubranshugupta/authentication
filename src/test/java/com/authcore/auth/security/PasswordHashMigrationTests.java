package com.authcore.auth.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;

import com.authcore.auth.user.UserRepository;

class PasswordHashMigrationTests {
    private final UserRepository users = mock(UserRepository.class);
    private final PasswordHashing.Bounded encoder = PasswordHashing.encoder();

    @Test
    void whileOldHashesAreLeftTheTimingStaysEqual() {
        when(users.anyOldPasswordHashes()).thenReturn(true);

        new PasswordHashMigration(users, encoder).checkForOldHashes();

        assertThat(encoder.isEqualTiming()).isTrue();
    }

    @Test
    void withNoneLeftItStops() {
        when(users.anyOldPasswordHashes()).thenReturn(false);

        new PasswordHashMigration(users, encoder).checkForOldHashes();

        assertThat(encoder.isEqualTiming()).isFalse();
    }
}
