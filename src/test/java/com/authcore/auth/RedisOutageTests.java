package com.authcore.auth;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.testcontainers.containers.GenericContainer;

import com.authcore.auth.support.IntegrationTest;

import jakarta.servlet.http.Cookie;

/** Nobody's login depends on Redis (A7). Without a timeout, every request waited a full minute. */
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
        try {
            login(email, PASSWORD).andExpect(status().isOk());
            getProfile(accessToken).andExpect(status().isOk());
            refresh(refreshCookie).andExpect(status().isOk());
            logout(refreshCookie).andExpect(status().isOk());
        } finally {
            redis.getDockerClient().unpauseContainerCmd(redis.getContainerId()).exec();
        }
    }
}
