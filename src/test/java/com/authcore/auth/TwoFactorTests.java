package com.authcore.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.ResultActions;

import com.jayway.jsonpath.JsonPath;

import com.authcore.auth.mfa.Totp;
import com.authcore.auth.support.IntegrationTest;
import com.authcore.auth.user.admin.AdminBootstrap;

/**
 * F5: two-factor authentication with an authenticator app. The tests act as the app: they
 * make codes from the secret the setup hands out.
 */
class TwoFactorTests extends IntegrationTest {
    private static final String ON = "Two-factor authentication is on for your AuthCore account";
    private static final String OFF = "Two-factor authentication is off for your AuthCore account";
    private static final String RECOVERY_USED = "A recovery code was used to sign in to AuthCore";
    private static final String NEW_PASSWORD = "N3w-Str0ng-Passw0rd!";

    @Autowired
    private AdminBootstrap adminBootstrap;

    // ---- setting it up ---------------------------------------------------------------

    @Test
    void theSetupNeedsThePasswordAndChangesNothingYet() throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);

        post2fa(accessToken, "/setup", "{\"currentPassword\": \"Wrong-passw0rd!\"}")
                .andExpect(status().isForbidden()).andExpect(jsonPath("$.code").value("WRONG_PASSWORD"));
        ResultActions setup = post2fa(accessToken, "/setup", password()).andExpect(status().isOk());
        String secret = read(setup, "$.secret");

        assertThat(secret).matches("[A-Z2-7]{32}");
        assertThat(read(setup, "$.otpauthUri").toString())
                .startsWith("otpauth://totp/AuthCore%3A" + email.replace("@", "%40") + "?secret=" + secret)
                .contains("&issuer=AuthCore", "&digits=6", "&period=30");
        twoFactorStatus(accessToken).andExpect(jsonPath("$.enabled").value(false));
        login(email, PASSWORD).andExpect(jsonPath("$.accessToken").isNotEmpty());
    }

    @Test
    void theFirstCodeTurnsItOnAndReturnsTenRecoveryCodes() throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);
        String secret = setUp(accessToken);

        post2fa(accessToken, "/enable", code("000000")).andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_CODE"));
        post2fa(accessToken, "/enable", code(appCode(secret, 0)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.recoveryCodes", hasSize(10)))
                .andExpect(jsonPath("$.recoveryCodes[0]").value(org.hamcrest.Matchers.matchesPattern("[a-z2-7]{5}-[a-z2-7]{5}")));

        twoFactorStatus(accessToken).andExpect(jsonPath("$.enabled").value(true)).andExpect(jsonPath("$.recoveryCodesLeft").value(10));
        assertThat(htmlBody(awaitEmail(email, ON))).contains("authenticator app");
        // Encrypted: the secret isn't in the database as it was handed out.
        byte[] stored = jdbc.queryForObject("select secret from totp_credentials where user_id = ?", byte[].class,
                user(email).getId());
        assertThat(stored).hasSize(49).isNotEqualTo(Totp.fromBase32(secret));
    }

    @Test
    void enablingNeedsASetupAndASecondSetupIsRefused() throws Exception {
        String accessToken = registerVerifiedUserAndLogin(uniqueEmail());

        post2fa(accessToken, "/enable", code("123456")).andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("TWO_FACTOR_NOT_SET_UP"));
        enable(accessToken);
        post2fa(accessToken, "/setup", password()).andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("TWO_FACTOR_ALREADY_ENABLED"));
    }

    @Test
    void aNewSetupReplacesAnUnfinishedOne() throws Exception {
        String accessToken = registerVerifiedUserAndLogin(uniqueEmail());
        String first = setUp(accessToken);
        String second = setUp(accessToken);

        if (!appCode(first, 0).equals(appCode(second, 0)))
            post2fa(accessToken, "/enable", code(appCode(first, 0))).andExpect(status().isBadRequest());
        post2fa(accessToken, "/enable", code(appCode(second, 0))).andExpect(status().isOk());
    }

    // ---- logging in ------------------------------------------------------------------

    @Test
    void thePasswordAloneOnlyGetsAChallenge() throws Exception {
        String email = uniqueEmail();
        enable(registerVerifiedUserAndLogin(email));

        login(email, PASSWORD)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.secondFactorRequired").value(true))
                .andExpect(jsonPath("$.challenge").isNotEmpty())
                .andExpect(jsonPath("$.accessToken").doesNotExist())
                .andExpect(header().doesNotExist(HttpHeaders.SET_COOKIE));
        login(email, "Wrong-passw0rd!").andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.challenge").doesNotExist());
    }

    @Test
    void theCodeCompletesTheLogin() throws Exception {
        String email = uniqueEmail();
        String secret = enable(registerVerifiedUserAndLogin(email));

        ResultActions done = secondStep(challenge(email), appCode(secret, 1))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.secondFactorRequired").doesNotExist());

        getProfile(accessToken(done)).andExpect(jsonPath("$.email").value(email));
        assertThat(done.andReturn().getResponse().getCookie("deviceId")).isNotNull();
        refresh(refreshCookie(done)).andExpect(status().isOk());
    }

    @Test
    void aCodeWorksOnce() throws Exception {
        String email = uniqueEmail();
        String secret = enable(registerVerifiedUserAndLogin(email));
        String code = appCode(secret, 1);
        secondStep(challenge(email), code).andExpect(status().isOk());

        secondStep(challenge(email), code)
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("INVALID_CREDENTIALS"));
    }

    @Test
    void theAppsClockMayBeAStepOff() throws Exception {
        String email = uniqueEmail();
        String secret = enable(registerVerifiedUserAndLogin(email));
        jdbc.update("update totp_credentials set last_used_step = 0 where user_id = ?", user(email).getId());

        secondStep(challenge(email), appCode(secret, -1)).andExpect(status().isOk());
        secondStep(challenge(email), appCode(secret, 1)).andExpect(status().isOk());
        jdbc.update("update totp_credentials set last_used_step = 0 where user_id = ?", user(email).getId());
        secondStep(challenge(email), appCode(secret, 2)).andExpect(status().isUnauthorized());
    }

    @Test
    void fiveWrongCodesStopTheChecksFor15Minutes() throws Exception {
        String email = uniqueEmail();
        String secret = enable(registerVerifiedUserAndLogin(email));
        String challenge = challenge(email);
        String right = appCode(secret, 1);
        String wrong = right.equals("000000") ? "111111" : "000000";

        for (int i = 0; i < 5; i++)
            secondStep(challenge, wrong).andExpect(status().isUnauthorized());
        secondStep(challenge, right)
                .andExpect(status().isTooManyRequests())
                .andExpect(header().exists(HttpHeaders.RETRY_AFTER));

        jdbc.update("update totp_credentials set last_failed_at = last_failed_at - interval 16 minute where user_id = ?",
                user(email).getId());
        secondStep(challenge, right).andExpect(status().isOk());
    }

    @Test
    void aRecoveryCodeWorksOnceInsteadOfTheAppAndIsEmailed() throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);
        String secret = setUp(accessToken);
        List<String> codes = recoveryCodes(post2fa(accessToken, "/enable", code(appCode(secret, 0))));

        // Typed as it comes, in capitals, or without the dash.
        secondStep(challenge(email), " " + codes.get(0).toUpperCase() + " ").andExpect(status().isOk());
        secondStep(challenge(email), codes.get(1).replace("-", "")).andExpect(status().isOk());
        secondStep(challenge(email), codes.get(0)).andExpect(status().isUnauthorized());

        awaitEmails(email, RECOVERY_USED, 2);
        twoFactorStatus(accessToken).andExpect(jsonPath("$.recoveryCodesLeft").value(8));
    }

    @Test
    void aMadeUpOrStaleChallengeMeansLoggingInAgain() throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);
        String secret = enable(accessToken);
        String challenge = challenge(email);

        secondStep("not-a-challenge", appCode(secret, 1)).andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("TWO_FACTOR_LOGIN_EXPIRED"));
        // An access token isn't a challenge, nor the other way round.
        secondStep(accessToken, appCode(secret, 1)).andExpect(jsonPath("$.code").value("TWO_FACTOR_LOGIN_EXPIRED"));
        getProfile(challenge).andExpect(status().isUnauthorized());

        // A password reset meanwhile.
        requestPasswordReset(email).andExpect(status().isOk());
        confirmPasswordReset(email, passwordResetOtp(email), NEW_PASSWORD).andExpect(status().isOk());
        secondStep(challenge, appCode(secret, 1)).andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("TWO_FACTOR_LOGIN_EXPIRED"));
    }

    @Test
    void aPasswordResetDoesNotTurnItOff() throws Exception {
        String email = uniqueEmail();
        enable(registerVerifiedUserAndLogin(email));

        requestPasswordReset(email).andExpect(status().isOk());
        confirmPasswordReset(email, passwordResetOtp(email), NEW_PASSWORD).andExpect(status().isOk());

        login(email, NEW_PASSWORD).andExpect(jsonPath("$.secondFactorRequired").value(true));
    }

    @Test
    void theSameCodeTwiceAtOnceLogsInOnce() throws Exception {
        String email = uniqueEmail();
        String secret = enable(registerVerifiedUserAndLogin(email));
        String challenge = challenge(email);
        String code = appCode(secret, 1);

        List<Integer> statuses = allAtOnce(4,
                () -> secondStep(challenge, code).andReturn().getResponse().getStatus());

        assertThat(statuses).containsOnlyOnce(200).containsOnly(200, 401);
    }

    // ---- turning it off, new recovery codes ---------------------------------------------

    @Test
    void turningItOffNeedsThePasswordAndACode() throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);
        String secret = enable(accessToken);

        post2fa(accessToken, "/disable", passwordAndCode("Wrong-passw0rd!", appCode(secret, 1)))
                .andExpect(status().isForbidden());
        post2fa(accessToken, "/disable", passwordAndCode(PASSWORD, "000000")).andExpect(status().isBadRequest());
        post2fa(accessToken, "/disable", passwordAndCode(PASSWORD, appCode(secret, 1))).andExpect(status().isOk());

        twoFactorStatus(accessToken).andExpect(jsonPath("$.enabled").value(false));
        login(email, PASSWORD).andExpect(jsonPath("$.accessToken").isNotEmpty());
        awaitEmail(email, OFF);
        assertThat(jdbc.queryForObject("select count(*) from recovery_codes where user_id = ?", Integer.class,
                user(email).getId())).isZero();
        post2fa(accessToken, "/disable", passwordAndCode(PASSWORD, appCode(secret, 1)))
                .andExpect(status().isConflict()).andExpect(jsonPath("$.code").value("TWO_FACTOR_NOT_ENABLED"));
    }

    @Test
    void newRecoveryCodesReplaceTheOldOnes() throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);
        String secret = setUp(accessToken);
        List<String> old = recoveryCodes(post2fa(accessToken, "/enable", code(appCode(secret, 0))));

        List<String> fresh = recoveryCodes(post2fa(accessToken, "/recovery-codes",
                passwordAndCode(PASSWORD, appCode(secret, 1))).andExpect(status().isOk()));

        assertThat(fresh).hasSize(10).doesNotContainAnyElementsOf(old);
        secondStep(challenge(email), old.get(0)).andExpect(status().isUnauthorized());
        secondStep(challenge(email), fresh.get(0)).andExpect(status().isOk());
    }

    @Test
    void deletingTheAccountDeletesItsSecretAndCodes() throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);
        enable(accessToken);
        int userId = user(email).getId();

        requestAccountDeletion(accessToken).andExpect(status().isOk());
        confirmAccountDeletion(accessToken, deleteAccountOtp(email), PASSWORD).andExpect(status().isOk());

        assertThat(jdbc.queryForObject("select count(*) from totp_credentials where user_id = ?", Integer.class, userId)).isZero();
        assertThat(jdbc.queryForObject("select count(*) from recovery_codes where user_id = ?", Integer.class, userId)).isZero();
    }

    // ---- admins --------------------------------------------------------------------------

    @Test
    void anAdminCanTurnItOffForAUserWhoLostEverything() throws Exception {
        String adminEmail = uniqueEmail();
        String admin = registerVerifiedUserAndLogin(adminEmail);
        adminBootstrap.promote(List.of(adminEmail));
        String email = uniqueEmail();
        enable(registerVerifiedUserAndLogin(email));
        int userId = user(email).getId();

        mvc.perform(as(admin, get("/api/v1/admin/users/" + userId))).andExpect(jsonPath("$.twoFactorEnabled").value(true));
        adminDisable(admin, userId)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.twoFactorEnabled").value(false));

        login(email, PASSWORD).andExpect(jsonPath("$.accessToken").isNotEmpty());
        assertThat(htmlBody(awaitEmail(email, OFF))).contains("An administrator turned two-factor authentication off");
        adminDisable(admin, userId).andExpect(status().isConflict());
        adminDisable(admin, user(adminEmail).getId()).andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("ADMIN_ACTION_REFUSED"));
    }

    @Test
    void usersCannotUseTheAdminEndpoint() throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);

        adminDisable(accessToken, user(email).getId()).andExpect(status().isForbidden());
    }

    // ---- helpers -------------------------------------------------------------------------

    private ResultActions post2fa(String accessToken, String path, String body) throws Exception {
        return mvc.perform(as(accessToken, post("/api/v1/users/me/2fa" + path))
                .contentType(MediaType.APPLICATION_JSON).content(body));
    }

    private ResultActions twoFactorStatus(String accessToken) throws Exception {
        return mvc.perform(as(accessToken, get("/api/v1/users/me/2fa")));
    }

    private ResultActions secondStep(String challenge, String code) throws Exception {
        return postJson("/api/v1/auth/login/2fa", "{\"challenge\": \"%s\", \"code\": \"%s\"}".formatted(challenge, code));
    }

    private ResultActions adminDisable(String admin, int userId) throws Exception {
        return mvc.perform(as(admin, post("/api/v1/admin/users/" + userId + "/2fa/disable"))
                .contentType(MediaType.APPLICATION_JSON).content(password().replace("currentPassword", "password")));
    }

    /** The password step of a login. */
    private String challenge(String email) throws Exception {
        return read(login(email, PASSWORD).andExpect(status().isOk()), "$.challenge");
    }

    /** Starts the setup, and returns the secret. */
    private String setUp(String accessToken) throws Exception {
        return read(post2fa(accessToken, "/setup", password()).andExpect(status().isOk()), "$.secret");
    }

    /** Turns it on with the code of this time step, and returns the secret. */
    private String enable(String accessToken) throws Exception {
        String secret = setUp(accessToken);
        post2fa(accessToken, "/enable", code(appCode(secret, 0))).andExpect(status().isOk());
        return secret;
    }

    /** What the app shows now, or {@code steps} steps from now. */
    private static String appCode(String secret, int steps) {
        return Totp.code(Totp.fromBase32(secret), Totp.step(Instant.now()) + steps);
    }

    private static List<String> recoveryCodes(ResultActions answer) throws Exception {
        return read(answer, "$.recoveryCodes");
    }

    private static <T> T read(ResultActions answer, String path) throws Exception {
        return JsonPath.read(answer.andReturn().getResponse().getContentAsString(), path);
    }

    private static String password() {
        return "{\"currentPassword\": \"%s\"}".formatted(PASSWORD);
    }

    private static String code(String code) {
        return "{\"code\": \"%s\"}".formatted(code);
    }

    private static String passwordAndCode(String password, String code) {
        return "{\"currentPassword\": \"%s\", \"code\": \"%s\"}".formatted(password, code);
    }

    private static List<Integer> allAtOnce(int threads, Callable<Integer> request) throws Exception {
        CountDownLatch start = new CountDownLatch(1);
        try (ExecutorService pool = Executors.newFixedThreadPool(threads)) {
            List<Future<Integer>> futures = new ArrayList<>();
            for (int i = 0; i < threads; i++)
                futures.add(pool.submit(() -> {
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
