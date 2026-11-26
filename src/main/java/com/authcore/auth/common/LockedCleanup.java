package com.authcore.auth.common;

import java.util.List;
import java.util.function.Function;

import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Component;

import com.authcore.auth.user.UserRepository;

import lombok.RequiredArgsConstructor;

/**
 * Deletes rows that nobody needs any more, a few users at a time (M5). Each batch locks its
 * users' rows first, like every request that changes something of a user does: a request
 * that already read a row would otherwise find it gone halfway through.
 */
@Component
@RequiredArgsConstructor
public class LockedCleanup {
    static final int USERS_PER_BATCH = 100;

    private final UserRepository userRepository;
    private final RetryingTransaction transaction;

    /**
     * @param findUsers   users that have rows to delete, at most a page of them
     * @param deleteRows  deletes those users' rows, returns how many
     * @return how many rows were deleted
     */
    public int run(Function<Pageable, List<Integer>> findUsers, Function<List<Integer>, Integer> deleteRows) {
        int deleted = 0;
        while (true) {
            List<Integer> users = findUsers.apply(PageRequest.of(0, USERS_PER_BATCH));
            if (users.isEmpty())
                return deleted;
            int batch = transaction.run(() -> {
                userRepository.lockAll(users);
                return deleteRows.apply(users);
            });
            // Somebody else deleted them meanwhile (e.g. the same job on another server).
            if (batch == 0)
                return deleted;
            deleted += batch;
        }
    }
}
