package com.authcore.auth.auth;

import org.jspecify.annotations.Nullable;

/**
 * What a login hands out: the tokens, or for a user with two-factor authentication after
 * the password, the challenge for the second step.
 *
 * @param deviceId  the id of the client's device, which it keeps in a cookie
 * @param challenge for {@code POST /api/v1/auth/login/2fa}; only when a code is still needed
 */
public record LoginResult(@Nullable TokenPair tokens, @Nullable String deviceId, @Nullable String challenge) {
    static LoginResult secondFactorRequired(String challenge) {
        return new LoginResult(null, null, challenge);
    }

    /** Leaves the tokens and the id out: logs must not contain them. */
    @Override
    public String toString() {
        return "LoginResult[...]";
    }
}
