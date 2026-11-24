package com.authcore.auth.service;

/** What a login hands out. The controller decides how each token reaches the client. */
public record TokenPair(String accessToken, String refreshToken) {
    /** Leaves the tokens out: logs must not contain them (H2). */
    @Override
    public String toString() {
        return "TokenPair[...]";
    }
}
