package com.authcore.auth;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.support.TransactionTemplate;

import com.authcore.auth.session.SessionCleanup;
import com.authcore.auth.support.IntegrationTest;
import com.authcore.auth.token.TokenCleanup;

import jakarta.servlet.http.Cookie;

/** M5: the jobs that delete expired sessions, old used refresh tokens and expired codes. */
class CleanupTests extends IntegrationTest {

    @Autowired
    private SessionCleanup sessionCleanup;

    @Autowired
    private TokenCleanup tokenCleanup;

    @Autowired
    private TransactionTemplate transaction;

    // ---- sessions ------------------------------------------------------------------

    @Test
    void expiredSessionsAreDeletedWithTheirTokensAndTheOthersStay() throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);
        Cookie phone = refreshCookie(email, PASSWORD);
        int userId = user(email).getId();
        long phoneSession = jdbc.queryForObject("select max(id) from user_sessions where user_id = ?", Long.class, userId);
        jdbc.update("update user_sessions set expires_at = utc_timestamp(6) - interval 1 second where id = ?", phoneSession);

        sessionCleanup.run();

        assertThat(count("select count(*) from user_sessions where user_id = ?", userId)).isEqualTo(1);
        assertThat(count("select count(*) from refresh_tokens where session_id = ?", phoneSession)).isZero();
        refresh(phone).andExpect(status().isUnauthorized());
        getProfile(accessToken).andExpect(status().isOk());
    }

    /** More users than one batch. */
    @Test
    void manyUsersAreCleanedUpInBatches() {
        List<Integer> users = new ArrayList<>();
        for (int i = 0; i < 250; i++) {
            String email = uniqueEmail();
            jdbc.update("insert into users (first_name, email, password, role, is_enabled, created_at, updated_at, token_version)"
                    + " values ('x', ?, 'x', 'USER', 1, utc_timestamp(6), utc_timestamp(6), 0)", email);
            int id = jdbc.queryForObject("select id from users where email = ?", Integer.class, email);
            jdbc.update("insert into user_sessions (user_id, ip, created_at, last_used_at, expires_at)"
                    + " values (?, '127.0.0.1', utc_timestamp(6) - interval 9 day, utc_timestamp(6) - interval 8 day, utc_timestamp(6) - interval 1 day)", id);
            users.add(id);
        }

        sessionCleanup.run();

        String ids = String.join(",", users.stream().map(String::valueOf).toList());
        assertThat(count("select count(*) from user_sessions where user_id in (" + ids + ")")).isZero();
        assertThat(count("select count(*) from users where id in (" + ids + ")")).isEqualTo(250);
    }

    // ---- devices -------------------------------------------------------------------

    /** F5: a device unseen for 90 days counts as new anyway, so it isn't kept. */
    @Test
    void devicesUnseenFor90DaysAreDeletedAndTheOthersStay() throws Exception {
        String email = uniqueEmail();
        registerVerifiedUserAndLogin(email);
        login(email, PASSWORD).andExpect(status().isOk()); // a second device (no cookie)
        int userId = user(email).getId();
        long old = jdbc.queryForObject("select min(id) from known_devices where user_id = ?", Long.class, userId);
        jdbc.update("update known_devices set last_seen_at = utc_timestamp(6) - interval 90 day - interval 1 second"
                + " where id = ?", old);

        sessionCleanup.run();

        assertThat(count("select count(*) from known_devices where user_id = ?", userId)).isEqualTo(1);
        assertThat(count("select count(*) from known_devices where id = ?", old)).isZero();
    }

    // ---- refresh tokens ------------------------------------------------------------

    /** Used ones are kept for reuse detection, as long as a browser could still have them. */
    @Test
    void usedRefreshTokensAreDeletedAfterSevenDays() throws Exception {
        String email = uniqueEmail();
        registerVerifiedUserAndLogin(email);
        Cookie first = refreshCookie(email, PASSWORD);
        Cookie second = nextCookie(first);
        Cookie third = nextCookie(second);
        jdbc.update("update refresh_tokens set used_at = utc_timestamp(6) - interval 7 day - interval 1 minute where token_hash = ?", hash(first));

        sessionCleanup.run();

        assertThat(count("select count(*) from refresh_tokens where token_hash = ?", hash(first))).isZero();
        assertThat(count("select count(*) from refresh_tokens where token_hash = ?", hash(second))).isEqualTo(1);
        assertThat(count("select count(*) from refresh_tokens where token_hash = ?", hash(third))).isEqualTo(1);
        nextCookie(third);
    }

    // ---- codes and links -----------------------------------------------------------

    @Test
    void expiredCodesAndLinksAreDeletedAndTheOthersStay() throws Exception {
        String expired = uniqueEmail();
        String valid = uniqueEmail();
        register(expired, PASSWORD).andExpect(status().isOk());
        register(valid, PASSWORD).andExpect(status().isOk());
        jdbc.update("update one_time_tokens set expires_at = utc_timestamp(6) - interval 1 second where user_id = ?", user(expired).getId());

        tokenCleanup.run();

        assertThat(count("select count(*) from one_time_tokens where user_id = ?", user(expired).getId())).isZero();
        assertThat(count("select count(*) from one_time_tokens where user_id = ?", user(valid).getId())).isEqualTo(1);
        verifyEmail(verificationToken(valid)).andExpect(status().isOk());
        // A new link for the other one works as usual: the cooldown went with the old row.
        resendVerification(expired).andExpect(status().isOk());
        awaitEmails(expired, "Verify Email", 2);
        verifyEmail(verificationToken(expired)).andExpect(status().isOk());
    }

    // ---- locking -------------------------------------------------------------------

    /** A request that has the user's lock finishes before the job deletes anything of the user. */
    @Test
    void theJobWaitsForTheUsersLock() throws Exception {
        String email = uniqueEmail();
        registerVerifiedUserAndLogin(email);
        int userId = user(email).getId();
        jdbc.update("update user_sessions set expires_at = utc_timestamp(6) - interval 1 second where user_id = ?", userId);
        CountDownLatch locked = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);

        try (ExecutorService threads = Executors.newFixedThreadPool(2)) {
            Future<?> request = threads.submit(() -> transaction.executeWithoutResult(status -> {
                userRepository.findAndLockById(userId);
                locked.countDown();
                await(release);
            }));
            assertThat(locked.await(10, TimeUnit.SECONDS)).isTrue();
            Future<?> job = threads.submit(sessionCleanup::run);

            Thread.sleep(500);
            assertThat(job.isDone()).isFalse();
            assertThat(count("select count(*) from user_sessions where user_id = ?", userId)).isEqualTo(1);

            release.countDown();
            request.get(10, TimeUnit.SECONDS);
            job.get(10, TimeUnit.SECONDS);
        }
        assertThat(count("select count(*) from user_sessions where user_id = ?", userId)).isZero();
    }

    // ---- helpers -------------------------------------------------------------------

    private int count(String query, Object... args) {
        return jdbc.queryForObject(query, Integer.class, args);
    }

    private static String hash(Cookie cookie) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(cookie.getValue().getBytes(UTF_8)));
    }

    private static void await(CountDownLatch latch) {
        try {
            latch.await(10, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
