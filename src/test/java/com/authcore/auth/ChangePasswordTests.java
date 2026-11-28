package com.authcore.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadLocalRandom;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import com.authcore.auth.support.IntegrationTest;

/** F5: a logged-in user changes their password, typing the current one again. */
class ChangePasswordTests extends IntegrationTest {
    private static final String PATH = "/api/v1/users/me/password";
    private static final String NEW_PASSWORD = "N3w-Str0ng-Passw0rd!";
    private static final String WRONG = "Wrong-passw0rd!";

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Test
    void theNewPasswordWorksAndTheOldOneDoesNot() throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);

        changePassword(accessToken, PASSWORD, NEW_PASSWORD)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                // The refresh token stays the same.
                .andExpect(header().doesNotExist(HttpHeaders.SET_COOKIE));

        login(email, PASSWORD).andExpect(status().isUnauthorized());
        login(email, NEW_PASSWORD).andExpect(status().isOk());
    }

    @Test
    void otherDevicesAreLoggedOutButThisOneIsNot() throws Exception {
        String email = uniqueEmail();
        registerVerifiedUserAndLogin(email);
        ResultActions laptop = login(email, PASSWORD);
        ResultActions phone = login(email, PASSWORD);
        String oldAccessToken = accessToken(laptop);

        String newAccessToken = accessToken(changePassword(oldAccessToken, PASSWORD, NEW_PASSWORD));

        getProfile(newAccessToken).andExpect(status().isOk());
        listSessions(newAccessToken).andExpect(jsonPath("$", hasSize(1))).andExpect(jsonPath("$[0].current").value(true));
        // The old access token stops working, like every other one (H6).
        getProfile(oldAccessToken).andExpect(status().isUnauthorized());
        getProfile(accessToken(phone)).andExpect(status().isUnauthorized());
        refresh(refreshCookie(phone)).andExpect(status().isUnauthorized());
        // This session's refresh token goes on working.
        getProfile(accessToken(refresh(refreshCookie(laptop)))).andExpect(status().isOk());
    }

    @Test
    void aWrongCurrentPasswordChangesNothing() throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);
        String phone = accessToken(email, PASSWORD);

        changePassword(accessToken, WRONG, NEW_PASSWORD)
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("WRONG_PASSWORD"))
                .andExpect(jsonPath("$.detail").value("The password is wrong."));

        // Not logged out (403, not 401), and nobody else either.
        getProfile(accessToken).andExpect(status().isOk());
        getProfile(phone).andExpect(status().isOk());
        login(email, PASSWORD).andExpect(status().isOk());
        login(email, NEW_PASSWORD).andExpect(status().isUnauthorized());
    }

    @Test
    void theNewPasswordFollowsThePolicy() throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);
        String tooLong = "é".repeat(37); // 74 bytes

        for (String weak : new String[] { "", "short-pass1", tooLong })
            changePassword(accessToken, PASSWORD, weak)
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.code").value("INVALID_INPUT"))
                    .andExpect(jsonPath("$.errors.newPassword").exists());

        login(email, PASSWORD).andExpect(status().isOk());
    }

    @Test
    void bothPasswordsAreNeeded() throws Exception {
        String accessToken = registerVerifiedUserAndLogin(uniqueEmail());

        perform(accessToken, "{\"newPassword\": \"%s\"}".formatted(NEW_PASSWORD))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.currentPassword").exists());
        perform(accessToken, "{\"currentPassword\": \"%s\"}".formatted(PASSWORD))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.newPassword").exists());
        perform(accessToken, "").andExpect(status().isBadRequest());
    }

    /** It is only checked, so a password from before the rules (H1) can still be changed. */
    @Test
    void anOldPasswordThatBreaksTodaysRulesCanStillBeChanged() throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);
        jdbc.update("update users set password = ? where email = ?", passwordEncoder.encode("short"), email);

        changePassword(accessToken, "short", NEW_PASSWORD).andExpect(status().isOk());

        login(email, NEW_PASSWORD).andExpect(status().isOk());
    }

    @Test
    void itNeedsALogin() throws Exception {
        mvc.perform(put(PATH).contentType(MediaType.APPLICATION_JSON).content(body(PASSWORD, NEW_PASSWORD)))
                .andExpect(status().isUnauthorized());
    }

    /** Like at login (H9), and they count there too: a stolen token can't guess the password. */
    @Test
    void wrongPasswordsAreLimitedLikeAtLogin() throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);
        String ip = randomIp();
        for (int i = 0; i < 5; i++)
            changePassword(accessToken, WRONG, NEW_PASSWORD, ip).andExpect(status().isForbidden());

        changePassword(accessToken, PASSWORD, NEW_PASSWORD, ip)
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.code").value("TOO_MANY_REQUESTS"))
                .andExpect(header().exists(HttpHeaders.RETRY_AFTER));
        mvc.perform(post("/api/v1/auth/login").with(from(ip)).contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\": \"%s\", \"password\": \"%s\"}".formatted(email, PASSWORD)))
                .andExpect(status().isTooManyRequests());
        login(email, PASSWORD).andExpect(status().isOk()); // the password hasn't changed

        // Only from that address.
        changePassword(accessToken, PASSWORD, NEW_PASSWORD, randomIp()).andExpect(status().isOk());
    }

    /**
     * Guesses at the old password don't matter any more (like after a reset): the account's
     * limit (50 an hour from all addresses) starts again.
     */
    @Test
    void aChangeClearsTheWrongPasswordsOfTheAccount() throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);
        for (int i = 0; i < 49; i++)
            wrongLogin(email, randomIp()).andExpect(status().isUnauthorized());

        changePassword(accessToken, PASSWORD, NEW_PASSWORD).andExpect(status().isOk());

        // Without the reset, the second would be the 51st.
        for (int i = 0; i < 2; i++)
            wrongLogin(email, randomIp()).andExpect(status().isUnauthorized());
        mvc.perform(post("/api/v1/auth/login").with(from(randomIp())).contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\": \"%s\", \"password\": \"%s\"}".formatted(email, NEW_PASSWORD)))
                .andExpect(status().isOk());
    }

    private ResultActions wrongLogin(String email, String ip) throws Exception {
        return mvc.perform(post("/api/v1/auth/login").with(from(ip)).contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\": \"%s\", \"password\": \"%s\"}".formatted(email, WRONG)));
    }

    /**
     * Two changes at the same moment, from the same session: exactly one wins, and its
     * password is the one that works. The other finds the password changed (403) or its
     * session's tokens replaced (401), and changes nothing.
     */
    @Test
    void ofTwoChangesAtTheSameMomentOnlyOneWins() throws Exception {
        for (int round = 0; round < 5; round++) {
            String email = uniqueEmail();
            String accessToken = registerVerifiedUserAndLogin(email);
            String first = "F1rst-Str0ng-Passw0rd!";
            String second = "S3cond-Str0ng-Passw0rd!";

            List<Integer> statuses = allAtOnce(
                    () -> changePassword(accessToken, PASSWORD, first).andReturn().getResponse().getStatus(),
                    () -> changePassword(accessToken, PASSWORD, second).andReturn().getResponse().getStatus());

            assertThat(statuses).as("round " + round).containsOnlyOnce(200);
            assertThat(statuses).as("round " + round).containsAnyOf(401, 403);
            String winner = statuses.get(0) == 200 ? first : second;
            String loser = winner.equals(first) ? second : first;
            login(email, winner).andExpect(status().isOk());
            login(email, loser).andExpect(status().isUnauthorized());
        }
    }

    // ---- helpers -------------------------------------------------------------------

    private ResultActions changePassword(String accessToken, String current, String newPassword) throws Exception {
        return changePassword(accessToken, current, newPassword, randomIp());
    }

    private ResultActions changePassword(String accessToken, String current, String newPassword, String ip)
            throws Exception {
        return mvc.perform(request(accessToken, body(current, newPassword)).with(from(ip)));
    }

    private ResultActions perform(String accessToken, String body) throws Exception {
        return mvc.perform(request(accessToken, body));
    }

    private static MockHttpServletRequestBuilder request(String accessToken, String body) {
        return as(accessToken, put(PATH)).contentType(MediaType.APPLICATION_JSON).content(body);
    }

    private static String body(String current, String newPassword) {
        return "{\"currentPassword\": \"%s\", \"newPassword\": \"%s\"}".formatted(current, newPassword);
    }

    private static String randomIp() {
        ThreadLocalRandom random = ThreadLocalRandom.current();
        return "10." + random.nextInt(256) + "." + random.nextInt(256) + "." + random.nextInt(1, 255);
    }

    @SafeVarargs
    private static List<Integer> allAtOnce(Callable<Integer>... requests) throws Exception {
        CountDownLatch start = new CountDownLatch(1);
        try (ExecutorService threads = Executors.newFixedThreadPool(requests.length)) {
            List<Future<Integer>> futures = new ArrayList<>();
            for (var request : requests)
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
