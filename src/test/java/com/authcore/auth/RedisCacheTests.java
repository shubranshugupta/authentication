package com.authcore.auth;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.Serializable;
import java.time.Instant;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.redis.core.RedisTemplate;

import com.authcore.auth.entities.RefreshToken;
import com.authcore.auth.entities.Role;
import com.authcore.auth.entities.User;
import com.authcore.auth.service.CacheService;
import com.authcore.auth.support.IntegrationTest;

/**
 * The Redis cache after the Boot 4 / Jackson 3 upgrade (M2). The connection itself is
 * also covered: Redis runs on a random port here, which only works because the app now
 * uses Spring Boot's spring.data.redis settings instead of a hard-coded localhost:6379.
 */
class RedisCacheTests extends IntegrationTest {

    @Autowired
    private CacheService<String, User> userCache;

    @Autowired
    private CacheService<String, RefreshToken> refreshTokenCache;

    @Autowired
    @Qualifier("redisTemplate")
    private RedisTemplate<String, Serializable> redisTemplate;

    @Test
    void aCachedUserReadsBackWithEveryField() {
        String key = "test-user-" + UUID.randomUUID();
        User user = sampleUser();

        userCache.save(key, user, 60_000L);
        User cached = userCache.getValue(key, User.class);

        assertThat(cached.getId()).isEqualTo(user.getId());
        assertThat(cached.getEmail()).isEqualTo(user.getEmail());
        assertThat(cached.getFirstName()).isEqualTo("jane");
        assertThat(cached.getRole()).isEqualTo(Role.USER);
        assertThat(cached.isEnabled()).isTrue();
    }

    @Test
    void aCachedRefreshTokenReadsBackWithItsUser() {
        String key = "test-refresh-token-" + UUID.randomUUID();
        RefreshToken token = RefreshToken.builder()
                .id(7)
                .refreshToken(UUID.randomUUID().toString())
                .expiryDate(Instant.parse("2030-01-01T00:00:00Z"))
                .user(sampleUser())
                .build();

        refreshTokenCache.save(key, token, 60_000L);
        RefreshToken cached = refreshTokenCache.getValue(key, RefreshToken.class);

        assertThat(cached.getRefreshToken()).isEqualTo(token.getRefreshToken());
        assertThat(cached.getExpiryDate()).isEqualTo(token.getExpiryDate());
        assertThat(cached.getUser().getEmail()).isEqualTo(token.getUser().getEmail());
        assertThat(cached.getUser().isEnabled()).isTrue();
    }

    @Test
    void entriesSavedWithAnExpiryGetATtlAndCanBeDeleted() {
        String key = "test-ttl-" + UUID.randomUUID();

        userCache.save(key, sampleUser(), 60_000L);
        assertThat(redisTemplate.getExpire(key)).isBetween(1L, 60L);
        assertThat(userCache.contains(key)).isTrue();

        userCache.delete(key);
        assertThat(userCache.contains(key)).isFalse();
        assertThat(userCache.getValue(key, User.class)).isNull();
    }

    private static User sampleUser() {
        User user = User.builder()
                .id(42)
                .firstName("jane")
                .lastName("doe")
                .email(uniqueEmail())
                .password("$2a$10$hash")
                .role(Role.USER)
                .build();
        user.setEnabled(true);
        return user;
    }
}
