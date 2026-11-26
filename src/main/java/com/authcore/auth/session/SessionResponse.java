package com.authcore.auth.session;

import java.time.Instant;

import org.jspecify.annotations.Nullable;

/**
 * A session as its user sees it.
 *
 * @param current whether it's the session this request was made with
 */
public record SessionResponse(
        Long id,
        @Nullable String device,
        String ip,
        Instant createdAt,
        Instant lastUsedAt,
        Instant expiresAt,
        boolean current) {

    static SessionResponse from(UserSession session, Long currentSessionId) {
        return new SessionResponse(
                session.getId(),
                session.getDevice(),
                session.getIp(),
                session.getCreatedAt(),
                session.getLastUsedAt(),
                session.getExpiresAt(),
                session.getId().equals(currentSessionId));
    }
}
