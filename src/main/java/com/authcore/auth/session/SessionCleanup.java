package com.authcore.auth.session;

import java.time.Instant;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import com.authcore.auth.common.AuthConfigProperties;
import com.authcore.auth.common.LockedCleanup;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Deletes expired sessions (with their refresh tokens), and used refresh tokens that no
 * browser can still have (M5). A login deletes its user's expired sessions too; this
 * catches the users who don't come back.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class SessionCleanup {
    private final UserSessionRepository sessionRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final LockedCleanup cleanup;
    private final AuthConfigProperties properties;

    @Scheduled(cron = "${auth.cleanup.cron}")
    public void run() {
        Instant now = Instant.now();
        int sessions = cleanup.run(
                page -> sessionRepository.findUsersWithExpiredSessions(now, page),
                users -> sessionRepository.deleteExpired(users, now));
        // Used tokens are kept for reuse detection (C2), but only as long as a cookie
        // could still hold them: its max age is the refresh expiration.
        Instant usedBefore = now.minusMillis(properties.getToken().getRefreshExpiration());
        int tokens = cleanup.run(
                page -> refreshTokenRepository.findUsersWithTokensUsedBefore(usedBefore, page),
                users -> refreshTokenRepository.deleteUsedBefore(users, usedBefore));
        if (sessions + tokens > 0)
            log.info("Deleted {} expired sessions and {} old used refresh tokens", sessions, tokens);
    }
}
