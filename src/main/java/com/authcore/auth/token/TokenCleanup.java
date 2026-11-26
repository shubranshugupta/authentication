package com.authcore.auth.token;

import java.time.Instant;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import com.authcore.auth.common.LockedCleanup;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Deletes expired codes and links (M5). An expired one can't be used or guessed any more,
 * and asking for a new one creates a new row.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class TokenCleanup {
    private final OneTimeTokenRepository tokenRepository;
    private final LockedCleanup cleanup;

    @Scheduled(cron = "${auth.cleanup.cron}")
    public void run() {
        Instant now = Instant.now();
        int deleted = cleanup.run(
                page -> tokenRepository.findUsersWithExpiredTokens(now, page),
                users -> tokenRepository.deleteExpired(users, now));
        if (deleted > 0)
            log.info("Deleted {} expired codes and links", deleted);
    }
}
