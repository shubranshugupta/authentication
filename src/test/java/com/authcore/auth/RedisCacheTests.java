package com.authcore.auth;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.Serializable;
import java.time.Instant;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.redis.core.RedisTemplate;

import com.authcore.auth.common.CacheService;
import com.authcore.auth.session.CachedRefreshToken;
import com.authcore.auth.support.IntegrationTest;

/**
 * The Redis cache after the Boot 4 / Jackson 3 upgrade (M2). The connection itself is
 * also covered: Redis runs on a random port here, which only works because the app now
 * uses Spring Boot's spring.data.redis settings instead of a hard-coded localhost:6379.
 */
class RedisCacheTests extends IntegrationTest {
    private static final CachedRefreshToken TOKEN = new CachedRefreshToken(7, 42,
            Instant.parse("2030-01-01T00:00:00Z"));

    @Autowired
    private CacheService<String, CachedRefreshToken> cache;

    @Autowired
    @Qualifier("redisTemplate")
    private RedisTemplate<String, Serializable> redisTemplate;

    @Test
    void aCachedRefreshTokenReadsBackWithEveryField() {
        String key = "test-refresh-token-" + UUID.randomUUID();

        cache.save(key, TOKEN, 60_000L);

        assertThat(cache.getValue(key, CachedRefreshToken.class)).isEqualTo(TOKEN);
    }

    @Test
    void entriesSavedWithAnExpiryGetATtlAndCanBeDeleted() {
        String key = "test-ttl-" + UUID.randomUUID();

        cache.save(key, TOKEN, 60_000L);
        assertThat(redisTemplate.getExpire(key)).isBetween(1L, 60L);
        assertThat(cache.contains(key)).isTrue();

        cache.delete(key);
        assertThat(cache.contains(key)).isFalse();
        assertThat(cache.getValue(key, CachedRefreshToken.class)).isNull();
    }
}
