package com.authcore.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Set;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;

import com.authcore.auth.support.IntegrationTest;

/** C3: whole users, password hash included, used to be kept in Redis forever. */
class CachedSecretsTests extends IntegrationTest {

    @Autowired
    private StringRedisTemplate redis;

    @Test
    void redisNeverHoldsPasswordHashesOrEntriesWithoutAnExpiry() throws Exception {
        String email = uniqueEmail();
        getProfile(registerVerifiedUserAndLogin(email)).andExpect(status().isOk());
        refresh(refreshCookie(email, PASSWORD)).andExpect(status().isOk());
        requestPasswordReset(email).andExpect(status().isOk());

        String hash = user(email).getPassword();
        Set<String> keys = redis.keys("*");
        for (String key : keys) {
            assertThat(redis.opsForValue().get(key)).as(key)
                    .doesNotContain(hash).doesNotContain(email).doesNotContain("$2a$");
            assertThat(redis.getExpire(key)).as("TTL of " + key).isPositive();
        }
    }
}
