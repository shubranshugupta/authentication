package com.authcore.auth.auth;

/**
 * What a login hands out.
 *
 * @param deviceId the id of the client's device, which it keeps in a cookie
 */
public record LoginResult(TokenPair tokens, String deviceId) {
    /** Leaves the tokens and the id out: logs must not contain them. */
    @Override
    public String toString() {
        return "LoginResult[...]";
    }
}
