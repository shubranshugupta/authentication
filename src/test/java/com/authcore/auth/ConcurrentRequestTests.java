package com.authcore.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Queue;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;

import com.authcore.auth.support.IntegrationTest;

import jakarta.servlet.http.Cookie;

/**
 * The same request sent several times at once (a double-click, or someone probing).
 * They all used to insert the same row, and all but one got 500.
 */
class ConcurrentRequestTests extends IntegrationTest {
    private static final int REQUESTS = 8;
    /** Whether the requests really overlap is up to the scheduler, so try a few times. */
    private static final int ROUNDS = 3;
    private static final int DEADLOCK_ROUNDS = 25;

    @Test
    void firstLoginsAllSucceedAndShareOneRefreshToken() throws Exception {
        for (int round = 0; round < ROUNDS; round++) {
            String email = uniqueEmail();
            register(email, PASSWORD);
            verifyEmail(verificationToken(email));
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

            assertThat(allAtOnce(() -> requestPasswordReset(email).andReturn().getResponse().getStatus())).containsOnly(200);
            assertSentOnce(email, "Password Reset");
        }
    }

    /**
     * H2, the same leak in the other email endpoint. Inserting the row that was just
     * deleted used to deadlock in MySQL, which needs more rounds to show up.
     */
    @Test
    void verificationResendsAllGetTheUsualAnswer() throws Exception {
        for (int round = 0; round < DEADLOCK_ROUNDS; round++) {
            String email = uniqueEmail();
            register(email, PASSWORD);
            verificationToken(email);
            jdbc.update("delete from one_time_tokens where user_id = ?", user(email).getId());

            assertThat(allAtOnce(() -> resendVerification(email).andReturn().getResponse().getStatus())).containsOnly(200);
            awaitEmails(email, "Verify Email", 2);
            assertThat(sentEmails(email, "Verify Email")).hasSize(2); // registration, and one resend
        }
    }

    /** C1: guesses sent all at once must not get around the limit. */
    @Test
    void parallelGuessesAreAllCounted() throws Exception {
        for (int round = 0; round < ROUNDS; round++) {
            String email = uniqueEmail();
            registerVerifiedUserAndLogin(email);
            requestPasswordReset(email);
            String otp = passwordResetOtp(email);

            assertThat(allAtOnce(() -> confirmPasswordReset(email, wrongOtp(otp)))).containsOnly(400);

            assertThat(jdbc.queryForObject("select attempts from one_time_tokens where user_id = ? and purpose = ?",
                    Integer.class, user(email).getId(), "PASSWORD_RESET")).isEqualTo(5);
            assertThat(confirmPasswordReset(email, otp)).isEqualTo(400);
        }
    }

    @Test
    void theRightCodeCanBeUsedOnlyOnceEvenAtTheSameMoment() throws Exception {
        for (int round = 0; round < ROUNDS; round++) {
            String email = uniqueEmail();
            registerVerifiedUserAndLogin(email);
            requestPasswordReset(email);
            String otp = passwordResetOtp(email);

            List<Integer> statuses = allAtOnce(() -> confirmPasswordReset(email, otp));

            assertThat(statuses).containsOnly(200, 400);
            assertThat(statuses.stream().filter(status -> status == 200)).hasSize(1);
        }
    }

    @Test
    void aLinkCanBeUsedOnlyOnceEvenAtTheSameMoment() throws Exception {
        for (int round = 0; round < ROUNDS; round++) {
            String email = uniqueEmail();
            register(email, PASSWORD);
            String token = verificationToken(email);

            List<Integer> statuses = allAtOnce(() -> verifyEmail(token).andReturn().getResponse().getStatus());

            assertThat(statuses).containsOnly(200, 400);
            assertThat(statuses.stream().filter(status -> status == 200)).hasSize(1);
        }
    }

    /** Different users must not get in each other's way. */
    @Test
    void resetRequestsOfDifferentUsersAllSucceed() throws Exception {
        for (int round = 0; round < ROUNDS; round++) {
            Queue<String> emails = new ConcurrentLinkedQueue<>();
            for (int i = 0; i < REQUESTS; i++) {
                String email = uniqueEmail();
                registerVerifiedUserAndLogin(email);
                emails.add(email);
            }
            List<String> all = List.copyOf(emails);

            assertThat(allAtOnce(() -> requestPasswordReset(emails.remove()).andReturn().getResponse().getStatus())).containsOnly(200);
            for (String email : all)
                awaitEmail(email, "Password Reset");
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
            assertSentOnce(email, "Delete Account");
        }
    }

    private int confirmPasswordReset(String email, String otp) throws Exception {
        return confirmPasswordReset(email, otp, "N3w-Str0ng-Passw0rd!").andReturn().getResponse().getStatus();
    }

    private void assertSentOnce(String email, String subject) throws Exception {
        awaitEmail(email, subject);
        assertThat(sentEmails(email, subject)).hasSize(1);
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
