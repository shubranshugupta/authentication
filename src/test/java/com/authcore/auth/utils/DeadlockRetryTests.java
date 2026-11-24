package com.authcore.auth.utils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;
import org.springframework.dao.CannotAcquireLockException;
import org.springframework.dao.DataIntegrityViolationException;

class DeadlockRetryTests {
    private final AtomicInteger calls = new AtomicInteger();

    @Test
    void triesAgainAfterADeadlock() {
        String result = DeadlockRetry.run(() -> {
            if (calls.incrementAndGet() < DeadlockRetry.MAX_ATTEMPTS)
                throw new CannotAcquireLockException("deadlock");
            return "done";
        });

        assertThat(result).isEqualTo("done");
        assertThat(calls).hasValue(DeadlockRetry.MAX_ATTEMPTS);
    }

    @Test
    void givesUpEventually() {
        assertThatThrownBy(() -> DeadlockRetry.run(() -> {
            calls.incrementAndGet();
            throw new CannotAcquireLockException("deadlock");
        })).isInstanceOf(CannotAcquireLockException.class);
        assertThat(calls).hasValue(DeadlockRetry.MAX_ATTEMPTS);
    }

    @Test
    void otherErrorsAreNotRetried() {
        assertThatThrownBy(() -> DeadlockRetry.run(() -> {
            calls.incrementAndGet();
            throw new DataIntegrityViolationException("duplicate");
        })).isInstanceOf(DataIntegrityViolationException.class);
        assertThat(calls).hasValue(1);
    }
}
