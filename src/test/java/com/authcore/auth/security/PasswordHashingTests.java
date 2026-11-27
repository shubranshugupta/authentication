package com.authcore.auth.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.support.TransactionOperations;

import com.authcore.auth.common.RetryingTransaction;
import com.authcore.auth.user.Role;
import com.authcore.auth.user.User;
import com.authcore.auth.user.UserRepository;

class PasswordHashingTests {
    private static final String PASSWORD = "Str0ng-Passw0rd!";

    private final PasswordEncoder encoder = PasswordHashing.encoder();

    @Test
    void newHashesAreArgon2idWithOwaspsSettings() {
        String hash = encoder.encode(PASSWORD);

        assertThat(hash).startsWith("{argon2}$argon2id$v=19$m=19456,t=2,p=1$");
        assertThat(encoder.matches(PASSWORD, hash)).isTrue();
        assertThat(encoder.matches("Wrong-passw0rd!", hash)).isFalse();
        assertThat(encoder.upgradeEncoding(hash)).isFalse();
        // Salted: the same password hashes differently each time.
        assertThat(encoder.encode(PASSWORD)).isNotEqualTo(hash);
    }

    @Test
    void oldBcryptHashesStillMatchAndAreUpgraded() {
        String old = new BCryptPasswordEncoder().encode(PASSWORD); // as stored before: no prefix

        assertThat(encoder.matches(PASSWORD, old)).isTrue();
        assertThat(encoder.matches("Wrong-passw0rd!", old)).isFalse();
        assertThat(encoder.upgradeEncoding(old)).isTrue();
        assertThat(encoder.matches(PASSWORD, "{bcrypt}" + old)).isTrue();
        assertThat(encoder.upgradeEncoding("{bcrypt}" + old)).isTrue();
    }

    @Test
    void noMoreHashesRunAtOnceThanAllowed() throws Exception {
        AtomicInteger running = new AtomicInteger();
        AtomicInteger most = new AtomicInteger();
        PasswordEncoder slow = new PasswordEncoder() {
            @Override
            public String encode(CharSequence raw) {
                most.accumulateAndGet(running.incrementAndGet(), Math::max);
                try {
                    Thread.sleep(50);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                running.decrementAndGet();
                return "hash";
            }

            @Override
            public boolean matches(CharSequence raw, String encoded) {
                return encode(raw).equals(encoded);
            }
        };
        PasswordEncoder bounded = new PasswordHashing.Bounded(slow, 2);

        try (ExecutorService threads = Executors.newFixedThreadPool(8)) {
            List<Future<?>> done = new ArrayList<>();
            for (int i = 0; i < 8; i++) {
                boolean encode = i % 2 == 0;
                done.add(threads.submit(() -> encode ? bounded.encode("x") : bounded.matches("x", "hash")));
            }
            for (Future<?> future : done)
                future.get();
        }

        assertThat(most).hasValue(2);
    }

    // ---- equal timing (H2) ------------------------------------------------------------------

    @Test
    void everyCheckAlsoChecksTheOtherKindSoTheyTakeAsLong() {
        List<String> checked = new ArrayList<>();
        PasswordEncoder recording = new PasswordEncoder() {
            @Override
            public String encode(CharSequence raw) {
                return "{argon2}dummy";
            }

            @Override
            public boolean matches(CharSequence raw, String encoded) {
                checked.add(encoded.startsWith("{argon2}") ? "argon2" : "bcrypt");
                return encoded.equals("{argon2}real") || encoded.equals("$2a$10$real");
            }
        };
        PasswordHashing.EqualTiming equal = new PasswordHashing.EqualTiming(recording);

        assertThat(equal.matches(PASSWORD, "{argon2}real")).isTrue();
        assertThat(checked).containsExactly("argon2", "bcrypt");
        checked.clear();
        assertThat(equal.matches(PASSWORD, "$2a$10$real")).isTrue();
        assertThat(checked).containsExactly("bcrypt", "argon2");
        checked.clear();

        equal.stop();
        assertThat(equal.matches(PASSWORD, "$2a$10$real")).isTrue();
        assertThat(checked).containsExactly("bcrypt");
    }

    @Test
    void theRealEncoderPadsUntilTold() {
        PasswordHashing.Bounded bounded = PasswordHashing.encoder();

        assertThat(bounded.isEqualTiming()).isTrue();
        bounded.stopEqualTiming();
        assertThat(bounded.isEqualTiming()).isFalse();
        assertThat(bounded.matches(PASSWORD, bounded.encode(PASSWORD))).isTrue();
    }

    // ---- the upgrade at login ------------------------------------------------------------

    @Test
    void theUpgradeReplacesTheHashButNotTheTokenVersion() {
        User user = user("old-hash");
        UserRepository users = mock(UserRepository.class);
        when(users.findAndLockById(7)).thenReturn(Optional.of(user));
        when(users.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

        upgrade(users).updatePassword(new LoginDetails(user("old-hash")), "{argon2}new-hash");

        assertThat(user.getPassword()).isEqualTo("{argon2}new-hash");
        assertThat(user.getTokenVersion()).isEqualTo(3);
    }

    @Test
    void aPasswordChangedSinceTheCheckIsKept() {
        User user = user("changed-meanwhile");
        UserRepository users = mock(UserRepository.class);
        when(users.findAndLockById(7)).thenReturn(Optional.of(user));

        upgrade(users).updatePassword(new LoginDetails(user("old-hash")), "{argon2}new-hash");

        assertThat(user.getPassword()).isEqualTo("changed-meanwhile");
        verify(users, never()).save(any());
    }

    @Test
    void aFailedUpgradeDoesNotFailTheLogin() {
        UserRepository users = mock(UserRepository.class);
        when(users.findAndLockById(7)).thenThrow(new IllegalStateException("database is down"));
        LoginDetails login = new LoginDetails(user("old-hash"));

        assertThat(upgrade(users).updatePassword(login, "{argon2}new-hash")).isSameAs(login);
    }

    private static PasswordUpgrade upgrade(UserRepository users) {
        return new PasswordUpgrade(users, new RetryingTransaction(TransactionOperations.withoutTransaction()));
    }

    private static User user(String passwordHash) {
        return User.builder().id(7).email("jane@example.com").firstName("Jane").password(passwordHash)
                .role(Role.USER).enabled(true).tokenVersion(3).build();
    }
}
