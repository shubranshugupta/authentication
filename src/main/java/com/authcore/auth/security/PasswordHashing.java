package com.authcore.auth.security;

import java.util.Map;
import java.util.concurrent.Semaphore;

import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * How passwords are hashed (F5). New hashes are Argon2id, stored as {@code {argon2}$argon2id$...};
 * hashes from before have no prefix and are bcrypt, which still match. A bcrypt hash is
 * replaced with an Argon2id one at its user's next login ({@link PasswordUpgrade}).
 *
 * <p>Argon2id with OWASP's minimum settings: 19 MiB of memory, 2 iterations, 1 lane. The
 * memory makes guessing on GPUs slow, but every hash takes it, so no more hashes run at once
 * than there are processors: more wouldn't finish sooner, and a burst of logins would use
 * hundreds of MiB. The others wait their turn.
 */
public final class PasswordHashing {
    static final String ARGON2 = "argon2";
    static final String BCRYPT = "bcrypt";

    private static final int SALT_BYTES = 16;
    private static final int HASH_BYTES = 32;
    private static final int PARALLELISM = 1;
    private static final int MEMORY_KIB = 19 * 1024;
    private static final int ITERATIONS = 2;

    private PasswordHashing() {
    }

    public static Bounded encoder() {
        DelegatingPasswordEncoder delegating = new DelegatingPasswordEncoder(ARGON2, Map.of(
                ARGON2, new Argon2PasswordEncoder(SALT_BYTES, HASH_BYTES, PARALLELISM, MEMORY_KIB, ITERATIONS),
                BCRYPT, new BCryptPasswordEncoder()));
        // The hashes from before this have no {id} prefix.
        delegating.setDefaultPasswordEncoderForMatches(new BCryptPasswordEncoder());
        return new Bounded(new EqualTiming(delegating), Math.max(2, Runtime.getRuntime().availableProcessors()));
    }

    /**
     * Makes every password check take as long, whether the hash is Argon2id, bcrypt, or
     * Spring's stand-in for an unknown email (an Argon2id hash). Otherwise a user with an old
     * bcrypt hash would answer more slowly than an unknown email, and the time would show which
     * emails are registered (H2). Each check also checks the other kind against a dummy hash.
     *
     * <p>Only while bcrypt hashes are left: once none are (checked at startup), it stops.
     */
    static final class EqualTiming implements PasswordEncoder {
        private final PasswordEncoder delegate;
        private final String bcryptDummy;
        private final String argon2Dummy;
        private volatile boolean enabled = true;

        EqualTiming(PasswordEncoder delegate) {
            this.delegate = delegate;
            this.bcryptDummy = "{" + BCRYPT + "}" + new BCryptPasswordEncoder().encode("dummy password");
            this.argon2Dummy = delegate.encode("dummy password");
        }

        @Override
        public String encode(CharSequence rawPassword) {
            return delegate.encode(rawPassword);
        }

        @Override
        public boolean matches(CharSequence rawPassword, String encodedPassword) {
            boolean matches = delegate.matches(rawPassword, encodedPassword);
            if (enabled)
                delegate.matches(rawPassword, isArgon2(encodedPassword) ? bcryptDummy : argon2Dummy);
            return matches;
        }

        @Override
        public boolean upgradeEncoding(String encodedPassword) {
            return delegate.upgradeEncoding(encodedPassword);
        }

        void stop() {
            enabled = false;
        }

        boolean isEnabled() {
            return enabled;
        }

        static boolean isArgon2(String encodedPassword) {
            return encodedPassword != null && encodedPassword.startsWith("{" + ARGON2 + "}");
        }
    }

    /** At most this many hashes at once. */
    public static final class Bounded implements PasswordEncoder {
        private final PasswordEncoder delegate;
        private final Semaphore permits;

        Bounded(PasswordEncoder delegate, int atOnce) {
            this.delegate = delegate;
            this.permits = new Semaphore(atOnce, true);
        }

        /** No bcrypt hashes are left: every check takes as long without the extra one. */
        void stopEqualTiming() {
            if (delegate instanceof EqualTiming equalTiming)
                equalTiming.stop();
        }

        boolean isEqualTiming() {
            return delegate instanceof EqualTiming equalTiming && equalTiming.isEnabled();
        }

        @Override
        public String encode(CharSequence rawPassword) {
            acquire();
            try {
                return delegate.encode(rawPassword);
            } finally {
                permits.release();
            }
        }

        @Override
        public boolean matches(CharSequence rawPassword, String encodedPassword) {
            acquire();
            try {
                return delegate.matches(rawPassword, encodedPassword);
            } finally {
                permits.release();
            }
        }

        /** True for a bcrypt hash: it gets replaced with an Argon2id one. Cheap, so not bounded. */
        @Override
        public boolean upgradeEncoding(String encodedPassword) {
            return delegate.upgradeEncoding(encodedPassword);
        }

        private void acquire() {
            try {
                permits.acquire();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("Interrupted while waiting to hash a password", e);
            }
        }
    }
}
