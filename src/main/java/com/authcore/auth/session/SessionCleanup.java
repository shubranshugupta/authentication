package com.authcore.auth.session;

import java.time.Instant;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import com.authcore.auth.common.AuthConfigProperties;
import com.authcore.auth.common.LockedCleanup;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Deletes expired sessions (with their refresh tokens), used refresh tokens that no
 * browser can still have (M5), and devices not seen for 90 days (F5). A login deletes its
 * user's expired sessions too; this catches the users who don't come back.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class SessionCleanup {
    private final UserSessionRepository sessionRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final KnownDeviceRepository deviceRepository;
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
        // A login from one of these would count as new anyway.
        Instant unseenSince = now.minus(DeviceService.REMEMBERED_FOR);
        int devices = cleanup.run(
                page -> deviceRepository.findUsersWithDevicesUnseenSince(unseenSince, page),
                users -> deviceRepository.deleteUnseenSince(users, unseenSince));
        if (sessions + tokens + devices > 0)
            log.info("Deleted {} expired sessions, {} old used refresh tokens and {} forgotten devices",
                    sessions, tokens, devices);
    }
}
