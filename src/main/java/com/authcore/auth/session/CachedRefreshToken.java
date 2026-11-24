package com.authcore.auth.session;

import java.io.Serializable;
import java.time.Instant;

/**
 * What the Redis cache keeps about a refresh token. Only ids: it used to hold the whole
 * user, password hash included (C3).
 */
public record CachedRefreshToken(Integer tokenId, Integer userId, Instant expiryDate) implements Serializable {
}
