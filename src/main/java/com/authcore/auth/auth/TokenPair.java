package com.authcore.auth.auth;

import java.time.Duration;

import org.jspecify.annotations.Nullable;

/**
 * What a login or refresh hands out. The controller decides how each token reaches the client.
 *
 * @param refreshToken    null if the client already has the latest one
 * @param refreshValidFor how long the refresh token lasts
 */
public record TokenPair(String accessToken, @Nullable String refreshToken, Duration refreshValidFor) {
    /** Leaves the tokens out: logs must not contain them (H2). */
    @Override
    public String toString() {
        return "TokenPair[...]";
    }
}
