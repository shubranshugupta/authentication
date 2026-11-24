package com.authcore.auth.common;

import java.util.function.Supplier;

import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionOperations;

import lombok.RequiredArgsConstructor;

/**
 * Runs an action in one database transaction, and again if MySQL rolled it back because of
 * a deadlock. Unlike @Transactional, the caller is outside the transaction: it can throw
 * after the commit, which would otherwise roll everything back.
 */
@Component
@RequiredArgsConstructor
public class RetryingTransaction {
    private final TransactionOperations transaction;

    public <T> T run(Supplier<T> action) {
        return DeadlockRetry.run(() -> transaction.execute(status -> action.get()));
    }
}
