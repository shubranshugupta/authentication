package com.authcore.auth.session;

import java.time.Duration;

import org.jspecify.annotations.Nullable;

/**
 * A session that was just opened or refreshed.
 *
 * @param refreshToken the new refresh token; null if the client already has it
 * @param validFor     how long the refresh token lasts
 */
public record SessionTokens(Integer userId, int tokenVersion, Long sessionId, @Nullable String refreshToken,
        Duration validFor) {
    /** Leaves the token out: logs must not contain it (H2). */
    @Override
    public String toString() {
        return "SessionTokens[sessionId=" + sessionId + "]";
    }
}
