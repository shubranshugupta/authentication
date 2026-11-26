package com.authcore.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.matchesPattern;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadLocalRandom;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.ResultActions;

import com.authcore.auth.support.IntegrationTest;

/** H9, C1 and H3: how often passwords and codes can be guessed, and emails be sent. */
class RateLimitTests extends IntegrationTest {
    private static final String WRONG = "Wrong-passw0rd!";
    private static final String NEW_PASSWORD = "N3w-Str0ng-Passw0rd!";

    @Autowired
    private StringRedisTemplate redis;

    private final String ip = randomIp();

    // ---- login ---------------------------------------------------------------------

    /** It used to accept any number. */
    @Test
    void after5WrongPasswordsEvenTheRightOneIsRefused() throws Exception {
        String email = verifiedUser();
        for (int i = 0; i < 5; i++)
            login(email, WRONG, ip).andExpect(status().isUnauthorized());

        login(email, PASSWORD, ip)
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.code").value("TOO_MANY_REQUESTS"))
                .andExpect(jsonPath("$.status").value(429))
                .andExpect(jsonPath("$.detail").value("Too many requests. Try again later."))
                .andExpect(header().string(HttpHeaders.RETRY_AFTER, matchesPattern("[1-9][0-9]{0,2}"))); // at most 900 s
    }

    @Test
    void the5thPasswordMayStillBeRight() throws Exception {
        String email = verifiedUser();
        for (int i = 0; i < 4; i++)
            login(email, WRONG, ip);

        login(email, PASSWORD, ip).andExpect(status().isOk());
    }

    /** Otherwise anyone could lock anyone out, with 5 wrong passwords. */
    @Test
    void theOwnerCanStillLogInFromElsewhere() throws Exception {
        String email = verifiedUser();
        for (int i = 0; i < 70; i++) // 5 are counted, the rest is refused and must not count
            login(email, WRONG, ip);

        login(email, PASSWORD, randomIp()).andExpect(status().isOk());
    }

    @Test
    void otherAccountsCanStillLogInFromTheSameAddress() throws Exception {
        String attacked = verifiedUser();
        String other = verifiedUser();
        for (int i = 0; i < 6; i++)
            login(attacked, WRONG, ip);

        login(other, PASSWORD, ip).andExpect(status().isOk());
    }

    @Test
    void anotherSpellingOfTheEmailIsTheSameAccount() throws Exception {
        String email = verifiedUser();
        for (int i = 0; i < 5; i++)
            login(i % 2 == 0 ? email.toUpperCase() : " " + email, WRONG, ip);

        login(email, PASSWORD, ip).andExpect(status().isTooManyRequests());
    }

    @Test
    void aSuccessfulLoginStartsOver() throws Exception {
        String email = verifiedUser();
        for (int round = 0; round < 3; round++) {
            for (int i = 0; i < 4; i++)
                login(email, WRONG, ip).andExpect(status().isUnauthorized());
            login(email, PASSWORD, ip).andExpect(status().isOk());
        }
    }

    @Test
    void successfulLoginsAreNotLimited() throws Exception {
        String email = verifiedUser();
        for (int i = 0; i < 60; i++)
            login(email, PASSWORD, ip).andExpect(status().isOk());
    }

    @Test
    void after15MinutesTheLimitIsOver() throws Exception {
        String email = verifiedUser();
        for (int i = 0; i < 6; i++)
            login(email, WRONG, ip);

        String key = redis.keys("rate-limit:LOGIN_PER_IP_AND_ACCOUNT:" + ip + ":*").iterator().next();
        assertThat(redis.getExpire(key)).isBetween(840L, 900L);
        redis.delete(key); // what Redis does then

        login(email, PASSWORD, ip).andExpect(status().isOk());
    }

    @Test
    void guessesFromManyAddressesAreLimitedPerAccount() throws Exception {
        String email = verifiedUser();
        for (int i = 0; i < 50; i++)
            login(email, WRONG, randomIp()).andExpect(status().isUnauthorized());

        login(email, PASSWORD, randomIp()).andExpect(status().isTooManyRequests());
    }

    @Test
    void guessesAtManyAccountsAreLimitedPerAddress() throws Exception {
        String email = verifiedUser();
        for (int i = 0; i < 50; i++)
            login(uniqueEmail(), WRONG, ip).andExpect(status().isUnauthorized());

        login(email, PASSWORD, ip).andExpect(status().isTooManyRequests());
        login(email, PASSWORD, randomIp()).andExpect(status().isOk());
    }

    /** H2 */
    @Test
    void unknownEmailsAreLimitedLikeKnownOnes() throws Exception {
        String known = verifiedUser();
        String unknown = uniqueEmail();
        for (int i = 0; i < 5; i++) {
            login(known, WRONG, ip).andExpect(status().isUnauthorized());
            login(unknown, WRONG, ip).andExpect(status().isUnauthorized());
        }

        assertThat(login(known, WRONG, ip).andExpect(status().isTooManyRequests()).andReturn().getResponse().getContentAsString())
                .isEqualTo(login(unknown, WRONG, ip).andExpect(status().isTooManyRequests()).andReturn().getResponse().getContentAsString());
    }

    @Test
    void parallelGuessesDontGetPastTheLimit() throws Exception {
        String email = verifiedUser();
        CountDownLatch start = new CountDownLatch(1);
        List<Integer> statuses = new ArrayList<>();
        try (ExecutorService threads = Executors.newFixedThreadPool(20)) {
            List<Future<Integer>> futures = new ArrayList<>();
            for (int i = 0; i < 20; i++)
                futures.add(threads.submit(() -> {
                    start.await();
                    return login(email, WRONG, ip).andReturn().getResponse().getStatus();
                }));
            start.countDown();
            for (Future<Integer> future : futures)
                statuses.add(future.get());
        }

        assertThat(statuses).containsOnly(401, 429);
        assertThat(statuses.stream().filter(status -> status == 401)).hasSize(5);
    }

    /** The password was right. */
    @Test
    void tryingBeforeTheEmailIsVerifiedIsNotAGuess() throws Exception {
        String email = uniqueEmail();
        register(email, PASSWORD);

        for (int i = 0; i < 10; i++)
            login(email, PASSWORD, ip).andExpect(status().isForbidden());
    }

    @Test
    void aPasswordResetLetsTheOwnerLogInAgain() throws Exception {
        String email = verifiedUser();
        for (int i = 0; i < 6; i++)
            login(email, WRONG, ip);
        for (int i = 0; i < 45; i++)
            login(email, WRONG, randomIp());
        login(email, PASSWORD, randomIp()).andExpect(status().isTooManyRequests());

        requestPasswordReset(email);
        postFrom(ip, "/api/v1/auth/password-reset/confirm", """
                {"email": "%s", "otp": "%s", "password": "%s"}
                """.formatted(email, passwordResetOtp(email), NEW_PASSWORD)).andExpect(status().isOk());

        login(email, NEW_PASSWORD, ip).andExpect(status().isOk());
    }

    /** One IPv6 customer has billions of addresses. */
    @Test
    void anIpv6NetworkCountsAsOneAddress() throws Exception {
        String email = verifiedUser();
        String network = "2001:db8:%x:%x".formatted(ThreadLocalRandom.current().nextInt(65536), ThreadLocalRandom.current().nextInt(65536));
        for (int i = 1; i <= 5; i++)
            login(email, WRONG, network + "::" + i).andExpect(status().isUnauthorized());

        login(email, PASSWORD, network + ":a:b:c:d").andExpect(status().isTooManyRequests());
    }

    // ---- other endpoints -----------------------------------------------------------

    @Test
    void registrationsArePerAddress() throws Exception {
        assertLimit(20, () -> postFrom(ip, "/api/v1/auth/register", """
                {"firstName": "jane", "email": "%s", "password": "%s"}
                """.formatted(uniqueEmail(), PASSWORD)), 200);
    }

    @Test
    void verificationEmailsArePerAddressAndPerAccount() throws Exception {
        assertLimit(20, () -> postEmail(ip, "/api/v1/auth/email-verification", uniqueEmail()), 200);
        String email = uniqueEmail();
        assertLimit(10, () -> postEmail(randomIp(), "/api/v1/auth/email-verification", email), 200);
    }

    @Test
    void resetEmailsArePerAddressAndPerAccount() throws Exception {
        assertLimit(20, () -> postEmail(ip, "/api/v1/auth/password-reset", uniqueEmail()), 200);
        String unknown = uniqueEmail();
        assertLimit(10, () -> postEmail(randomIp(), "/api/v1/auth/password-reset", unknown), 200);
        // H2: the same for an account that exists.
        String known = verifiedUser();
        assertLimit(10, () -> postEmail(randomIp(), "/api/v1/auth/password-reset", known), 200);
        assertThat(sentEmails(known, "Password Reset")).hasSizeLessThanOrEqualTo(1);
    }

    @Test
    void verificationLinksArePerAddress() throws Exception {
        assertLimit(30, () -> postFrom(ip, "/api/v1/auth/email-verification/confirm", "{\"token\": \"x\"}"), 400);
    }

    @Test
    void resetCodesArePerAddressAndPerAccountFromOneAddress() throws Exception {
        assertLimit(30, () -> confirmReset(ip, uniqueEmail()), 400);
        String email = uniqueEmail();
        String otherIp = randomIp();
        assertLimit(10, () -> confirmReset(otherIp, email), 400);
    }

    /** One address can't keep using up the codes of somebody else. */
    @Test
    void theOwnerCanStillUseTheirCode() throws Exception {
        String email = verifiedUser();
        for (int i = 0; i < 12; i++)
            confirmReset(ip, email);
        requestPasswordReset(email);
        String otp = passwordResetOtp(email);
        confirmReset(ip, email).andExpect(status().isTooManyRequests());

        confirmPasswordReset(email, otp, NEW_PASSWORD).andExpect(status().isOk());
    }

    @Test
    void deletionEmailsArePerUser() throws Exception {
        String accessToken = registerVerifiedUserAndLogin(uniqueEmail());
        requestAccountDeletion(accessToken).andExpect(status().isOk());
        assertLimit(9, () -> requestAccountDeletion(accessToken), 409);

        requestAccountDeletion(registerVerifiedUserAndLogin(uniqueEmail())).andExpect(status().isOk());
    }

    /** What is refused as invalid never reaches a limit. */
    @Test
    void invalidInputIsNotCounted() throws Exception {
        for (int i = 0; i < 25; i++)
            postFrom(ip, "/api/v1/auth/register", "{}").andExpect(status().isBadRequest());

        postFrom(ip, "/api/v1/auth/register", """
                {"firstName": "jane", "email": "%s", "password": "%s"}
                """.formatted(uniqueEmail(), PASSWORD)).andExpect(status().isOk());
    }

    // ---- storage and headers -------------------------------------------------------

    @Test
    void everyCounterExpiresAndHasNoEmailAddress() throws Exception {
        String email = verifiedUser();
        login(email, WRONG, ip);
        postEmail(ip, "/api/v1/auth/password-reset", email);

        Set<String> keys = redis.keys("*");
        assertThat(keys).isNotEmpty().noneMatch(key -> key.contains("@"));
        assertThat(keys).allMatch(key -> redis.getExpire(key) > 0);
    }

    @Test
    void scriptsCanReadHowLongToWait() throws Exception {
        mvc.perform(post("/api/v1/auth/login").header(HttpHeaders.ORIGIN, "http://localhost:3000")
                .contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS, HttpHeaders.RETRY_AFTER));
    }

    // ---- helpers -------------------------------------------------------------------

    private void assertLimit(int max, Request request, int usualStatus) throws Exception {
        for (int i = 0; i < max; i++)
            request.send().andExpect(status().is(usualStatus));
        request.send()
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.code").value("TOO_MANY_REQUESTS"))
                .andExpect(header().exists(HttpHeaders.RETRY_AFTER));
    }

    private interface Request {
        ResultActions send() throws Exception;
    }

    private String verifiedUser() throws Exception {
        String email = uniqueEmail();
        register(email, PASSWORD).andExpect(status().isOk());
        verifyEmail(verificationToken(email)).andExpect(status().isOk());
        return email;
    }

    private ResultActions login(String email, String password, String ip) throws Exception {
        return postFrom(ip, "/api/v1/auth/login", """
                {"email": "%s", "password": "%s"}
                """.formatted(email, password));
    }

    private ResultActions postEmail(String ip, String path, String email) throws Exception {
        return postFrom(ip, path, """
                {"email": "%s"}
                """.formatted(email));
    }

    private ResultActions confirmReset(String ip, String email) throws Exception {
        return postFrom(ip, "/api/v1/auth/password-reset/confirm", """
                {"email": "%s", "otp": "00000000", "password": "%s"}
                """.formatted(email, NEW_PASSWORD));
    }

    private ResultActions postFrom(String ip, String path, String body) throws Exception {
        return mvc.perform(post(path).contentType(MediaType.APPLICATION_JSON).content(body).with(from(ip)));
    }

    /** Not from 10.0.0.0/8, where every other request comes from. */
    private static String randomIp() {
        ThreadLocalRandom random = ThreadLocalRandom.current();
        return "100." + random.nextInt(256) + "." + random.nextInt(256) + "." + random.nextInt(256);
    }
}
