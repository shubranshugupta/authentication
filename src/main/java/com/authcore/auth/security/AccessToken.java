package com.authcore.auth.security;

/** What a valid access token says. */
public record AccessToken(Integer userId, int tokenVersion, Long sessionId) {
}
