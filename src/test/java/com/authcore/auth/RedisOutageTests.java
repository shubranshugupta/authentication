package com.authcore.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Duration;
import java.time.Instant;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.ResultActions;
import org.testcontainers.containers.GenericContainer;

import com.authcore.auth.support.IntegrationTest;

import jakarta.servlet.http.Cookie;

/**
 * Nobody's login depends on Redis: it only has the rate limits (A7), which are off while it's
 * down. Without a timeout, every request waited a full minute.
 */
class RedisOutageTests extends IntegrationTest {

    @Autowired
    @Qualifier("redisContainer")
    private GenericContainer<?> redis;

    @Test
    void everythingWorksWhileRedisIsSilent() throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);
        Cookie refreshCookie = refreshCookie(email, PASSWORD);

        redis.getDockerClient().pauseContainerCmd(redis.getContainerId()).exec();
        Instant start = Instant.now();
        try {
            login(email, PASSWORD).andExpect(status().isOk());
            getProfile(accessToken).andExpect(status().isOk());
            refresh(refreshCookie).andExpect(status().isOk());
            logout(refreshCookie).andExpect(status().isOk());
            login(email, "Wrong-passw0rd!").andExpect(status().isUnauthorized());
            register(uniqueEmail(), PASSWORD).andExpect(status().isOk());
            requestPasswordReset(email).andExpect(status().isOk());
            requestAccountDeletion(accessToken(email, PASSWORD)).andExpect(status().isOk());
            assertThat(Duration.between(start, Instant.now())).isLessThan(Duration.ofSeconds(10));
        } finally {
            redis.getDockerClient().unpauseContainerCmd(redis.getContainerId()).exec();
            Thread.sleep(6000); // the limits are back 5 seconds after the last failure
        }

        for (int i = 0; i < 5; i++)
            loginFrom("203.0.113.99", email).andExpect(status().isUnauthorized());
        loginFrom("203.0.113.99", email).andExpect(status().isTooManyRequests());
    }

    private ResultActions loginFrom(String ip, String email) throws Exception {
        return mvc.perform(post("/api/v1/auth/login").with(from(ip)).contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\": \"%s\", \"password\": \"Wrong-passw0rd!\"}".formatted(email)));
    }
}
