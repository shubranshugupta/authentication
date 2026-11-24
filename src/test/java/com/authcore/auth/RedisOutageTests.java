package com.authcore.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Duration;
import java.time.Instant;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.testcontainers.containers.GenericContainer;

import com.authcore.auth.support.IntegrationTest;

/** Without a timeout, every request waited a full minute when Redis didn't answer. */
class RedisOutageTests extends IntegrationTest {

    @Autowired
    @Qualifier("redisContainer")
    private GenericContainer<?> redis;

    @Test
    void requestsFailWithinSecondsWhileRedisIsSilentAndWorkAgainAfterwards() throws Exception {
        String email = uniqueEmail();
        registerVerifiedUserAndLogin(email);

        redis.getDockerClient().pauseContainerCmd(redis.getContainerId()).exec();
        try {
            Instant start = Instant.now();
            login(email, PASSWORD)
                    .andExpect(status().isInternalServerError())
                    .andExpect(jsonPath("$.detail").value("An unexpected error occurred."));
            assertThat(Duration.between(start, Instant.now())).isLessThan(Duration.ofSeconds(10));
        } finally {
            redis.getDockerClient().unpauseContainerCmd(redis.getContainerId()).exec();
        }

        login(email, PASSWORD).andExpect(status().isOk());
    }
}
