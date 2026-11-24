package com.authcore.auth.common;

import java.util.function.Supplier;

import org.springframework.dao.CannotAcquireLockException;

/**
 * Runs a database change again when MySQL picked it as the victim of a deadlock, which
 * is what MySQL expects its clients to do. It happens when the same row is inserted
 * several times at once just after an older copy of it was deleted.
 *
 * <p>The action must be safe to repeat, and not be part of a larger transaction (the
 * deadlock rolled that back).
 */
public final class DeadlockRetry {
    static final int MAX_ATTEMPTS = 3;

    private DeadlockRetry() {
    }

    public static <T> T run(Supplier<T> action) {
        for (int attempt = 1;; attempt++) {
            try {
                return action.get();
            } catch (CannotAcquireLockException e) {
                if (attempt == MAX_ATTEMPTS)
                    throw e;
            }
        }
    }
}
