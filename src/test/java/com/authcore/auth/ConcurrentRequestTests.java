package com.authcore.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.jdbc.core.JdbcTemplate;

import com.authcore.auth.support.IntegrationTest;

import jakarta.servlet.http.Cookie;

/**
 * The same request sent several times at once (a double-click, or someone probing).
 * They all used to insert the same row, and all but one got 500.
 */
class ConcurrentRequestTests extends IntegrationTest {
    @Autowired
    private JdbcTemplate jdbc;

    private static final int REQUESTS = 8;
    /** Whether the requests really overlap is up to the scheduler, so try a few times. */
    private static final int ROUNDS = 3;
    private static final int DEADLOCK_ROUNDS = 25;

    @Test
    void firstLoginsAllSucceedAndShareOneRefreshToken() throws Exception {
        for (int round = 0; round < ROUNDS; round++) {
            String email = uniqueEmail();
            register(email, PASSWORD);
            verifyEmail(email, verificationToken(email));
            List<String> refreshTokens = Collections.synchronizedList(new ArrayList<>());

            List<Integer> statuses = allAtOnce(() -> {
                var response = login(email, PASSWORD).andReturn().getResponse();
                Cookie cookie = response.getCookie("refreshToken");
                if (cookie != null)
                    refreshTokens.add(cookie.getValue());
                return response.getStatus();
            });

            assertThat(statuses).containsOnly(200);
            assertThat(refreshTokens).hasSize(REQUESTS);
            assertThat(refreshTokens.stream().distinct()).hasSize(1);
        }
    }

    @Test
    void registeringOneEmailCreatesOneAccountAndTheOthersGet409() throws Exception {
        for (int round = 0; round < ROUNDS; round++) {
            String email = uniqueEmail();

            List<Integer> statuses = allAtOnce(() -> register(email, PASSWORD).andReturn().getResponse().getStatus());

            assertThat(statuses).containsOnly(200, 409);
            assertThat(statuses.stream().filter(status -> status == 200)).hasSize(1);
            assertThat(verificationToken(email)).isNotEmpty();
        }
    }

    /** H2: unknown emails always got 200, so a 500 showed that the account exists. */
    @Test
    void passwordResetRequestsAllGetTheUsualAnswer() throws Exception {
        for (int round = 0; round < ROUNDS; round++) {
            String email = uniqueEmail();
            registerVerifiedUserAndLogin(email);

            assertThat(allAtOnce(() -> mvc.perform(post("/auth/reset-password").param("email", email))
                    .andReturn().getResponse().getStatus())).containsOnly(200);
            assertThat(passwordResetOtp(email)).isNotEmpty();
        }
    }

    /**
     * H2, the same leak in the other email endpoint. Inserting the row that was just
     * deleted can also deadlock in MySQL, which needs more rounds to show up.
     */
    @Test
    void verificationResendsAllGetTheUsualAnswer() throws Exception {
        for (int round = 0; round < DEADLOCK_ROUNDS; round++) {
            String email = uniqueEmail();
            register(email, PASSWORD);
            verificationTokenRepository.deleteAllByIdInBatch(
                    List.of(verificationTokenRepository.findByUser(user(email)).orElseThrow().getId()));

            assertThat(allAtOnce(() -> mvc.perform(get("/auth/verify-email").param("email", email))
                    .andReturn().getResponse().getStatus())).containsOnly(200);
            assertThat(verificationToken(email)).isNotEmpty();
        }
    }

    /** The same for a login whose old refresh token has expired: it's deleted and replaced. */
    @Test
    void loginsThatReplaceAnExpiredRefreshTokenAllSucceed() throws Exception {
        for (int round = 0; round < ROUNDS; round++) {
            String email = uniqueEmail();
            registerVerifiedUserAndLogin(email);
            jdbc.update("update refresh_tokens set expiry_date = '2020-01-01' where user_id = ?", user(email).getId());

            assertThat(allAtOnce(() -> login(email, PASSWORD).andReturn().getResponse().getStatus()))
                    .containsOnly(200);
        }
    }

    @Test
    void accountDeletionRequestsSendOneCodeAndTheOthersGet409() throws Exception {
        for (int round = 0; round < ROUNDS; round++) {
            String email = uniqueEmail();
            String accessToken = registerVerifiedUserAndLogin(email);

            List<Integer> statuses = allAtOnce(() -> mvc.perform(delete("/user/delete")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)).andReturn().getResponse().getStatus());

            assertThat(statuses).containsOnly(200, 409);
            assertThat(statuses.stream().filter(status -> status == 200)).hasSize(1);
        }
    }

    /** Runs the request on every thread at the same moment and returns the statuses. */
    private static List<Integer> allAtOnce(Callable<Integer> request) throws Exception {
        CountDownLatch start = new CountDownLatch(1);
        try (ExecutorService threads = Executors.newFixedThreadPool(REQUESTS)) {
            List<Future<Integer>> futures = new ArrayList<>();
            for (int i = 0; i < REQUESTS; i++)
                futures.add(threads.submit(() -> {
                    start.await();
                    return request.call();
                }));
            start.countDown();

            List<Integer> statuses = new ArrayList<>();
            for (Future<Integer> future : futures)
                statuses.add(future.get());
            return statuses;
        }
    }
}
