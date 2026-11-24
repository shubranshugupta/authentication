package com.authcore.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Duration;
import java.time.Instant;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.test.web.servlet.ResultActions;
import org.testcontainers.containers.GenericContainer;

import com.authcore.auth.support.IntegrationTest;

import jakarta.servlet.http.Cookie;

/** Without a timeout, every request waited a full minute when Redis didn't answer. */
class RedisOutageTests extends IntegrationTest {

    @Autowired
    @Qualifier("redisContainer")
    private GenericContainer<?> redis;

    @Test
    void onlyRefreshNeedsRedisAndItFailsWithinSecondsWhileRedisIsSilent() throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);
        Cookie refreshCookie = refreshCookie(email, PASSWORD);

        redis.getDockerClient().pauseContainerCmd(redis.getContainerId()).exec();
        try {
            // Users are no longer cached (C3), so these don't touch Redis at all.
            login(email, PASSWORD).andExpect(status().isOk());
            getProfile(accessToken).andExpect(status().isOk());

            Instant start = Instant.now();
            refresh(refreshCookie)
                    .andExpect(status().isInternalServerError())
                    .andExpect(jsonPath("$.detail").value("An unexpected error occurred."));
            assertThat(Duration.between(start, Instant.now())).isLessThan(Duration.ofSeconds(10));
        } finally {
            redis.getDockerClient().unpauseContainerCmd(redis.getContainerId()).exec();
        }

        refresh(refreshCookie).andExpect(status().isOk());
    }

    private ResultActions refresh(Cookie refreshCookie) throws Exception {
        return mvc.perform(post("/auth/refresh").cookie(refreshCookie));
    }
}
