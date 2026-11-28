package com.authcore.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import com.authcore.auth.support.IntegrationTest;

import jakarta.mail.internet.MimeMessage;
import jakarta.servlet.http.Cookie;

/**
 * F5: the owner hears of logins from new devices, password changes and resets, and of a
 * copied refresh token. Devices are remembered by a cookie ("deviceId").
 */
class SecurityEmailTests extends IntegrationTest {
    private static final String NEW_DEVICE = "New sign-in to your AuthCore account";
    private static final String CHANGED = "Your AuthCore password was changed";
    private static final String RESET = "Your AuthCore password was reset";
    private static final String ENDED = "You were logged out of AuthCore everywhere";
    private static final String NEW_PASSWORD = "N3w-Str0ng-Passw0rd!";
    private static final String DEVICE_ID = "[A-Za-z0-9_-]{43}";
    /** Long enough for an email that was going to be sent to have been. */
    private static final long QUIET_MILLIS = 700;

    // ---- the device cookie ---------------------------------------------------------

    @Test
    void theFirstLoginAfterSigningUpIsNoNewsButRemembersTheDevice() throws Exception {
        String email = registeredUser();

        MockHttpServletResponse login = login(email, PASSWORD, null, "Firefox").andExpect(status().isOk())
                .andReturn().getResponse();

        Cookie device = login.getCookie("deviceId");
        assertThat(device).isNotNull();
        assertThat(device.getValue()).matches(DEVICE_ID);
        assertThat(device.isHttpOnly()).isTrue();
        assertThat(device.getPath()).isEqualTo("/api/v1/auth");
        assertThat(device.getMaxAge()).isEqualTo(90 * 24 * 3600);
        assertThat(setCookie(login, "deviceId")).contains("SameSite=Strict");
        // Only its hash is stored.
        assertThat(jdbc.queryForList("select device_hash from known_devices where user_id = ?", String.class,
                user(email).getId())).hasSize(1).doesNotContain(device.getValue());
        assertNoEmail(email, NEW_DEVICE);
    }

    @Test
    void aLoginFromAKnownDeviceIsNoNews() throws Exception {
        String email = registeredUser();
        Cookie device = deviceCookie(login(email, PASSWORD, null, "Firefox"));

        Cookie again = deviceCookie(login(email, PASSWORD, device, "Firefox"));

        assertThat(again.getValue()).isEqualTo(device.getValue());
        assertNoEmail(email, NEW_DEVICE);
    }

    @Test
    void aLoginFromANewDeviceIsEmailedWithWhenAndWhere() throws Exception {
        String email = registeredUser();
        login(email, PASSWORD, null, "Firefox");

        login(email, PASSWORD, null, "Phone browser", "203.0.113.9").andExpect(status().isOk());

        String html = htmlBody(awaitEmail(email, NEW_DEVICE));
        assertThat(html).contains("Phone browser", "203.0.113.9", "UTC", "Forgot password");
        assertQuietly(email, NEW_DEVICE, 1);
    }

    @Test
    void aMadeUpDeviceIdIsReplacedAndCountsAsNew() throws Exception {
        String email = registeredUser();
        login(email, PASSWORD, null, "Firefox");

        Cookie replaced = deviceCookie(login(email, PASSWORD, new Cookie("deviceId", "not-an-id"), "Firefox"));

        assertThat(replaced.getValue()).matches(DEVICE_ID);
        awaitEmail(email, NEW_DEVICE);
    }

    @Test
    void aDeviceUnseenFor90DaysIsNewAgain() throws Exception {
        String email = registeredUser();
        Cookie device = deviceCookie(login(email, PASSWORD, null, "Firefox"));
        jdbc.update("update known_devices set last_seen_at = utc_timestamp(6) - interval 91 day where user_id = ?",
                user(email).getId());

        login(email, PASSWORD, device, "Firefox").andExpect(status().isOk());

        awaitEmail(email, NEW_DEVICE);
        // Seen now, so the next login is no news.
        login(email, PASSWORD, device, "Firefox").andExpect(status().isOk());
        assertQuietly(email, NEW_DEVICE, 1);
    }

    /** The exception for signing up is only for new accounts: a dormant one is emailed. */
    @Test
    void theFirstLoginOfAnOlderAccountIsEmailed() throws Exception {
        String email = registeredUser();
        jdbc.update("update users set created_at = utc_timestamp(6) - interval 2 day where email = ?", email);

        login(email, PASSWORD, null, "Firefox").andExpect(status().isOk());

        awaitEmail(email, NEW_DEVICE);
    }

    /** One browser, two accounts: each remembers it for itself. */
    @Test
    void aDeviceKnownToOneAccountIsNewToAnother() throws Exception {
        String first = registeredUser();
        Cookie browser = deviceCookie(login(first, PASSWORD, null, "Firefox"));
        String second = registeredUser();
        login(second, PASSWORD, null, "Chrome");

        Cookie same = deviceCookie(login(second, PASSWORD, browser, "Firefox"));

        assertThat(same.getValue()).isEqualTo(browser.getValue());
        awaitEmail(second, NEW_DEVICE);
        assertNoEmail(first, NEW_DEVICE);
    }

    @Test
    void parallelLoginsFromOneNewDeviceSendOneEmail() throws Exception {
        String email = registeredUser();
        login(email, PASSWORD, null, "Firefox");
        Cookie newDevice = new Cookie("deviceId", "a".repeat(43));

        List<Integer> statuses = allAtOnce(8, () -> login(email, PASSWORD, newDevice, "Firefox")
                .andReturn().getResponse().getStatus());

        assertThat(statuses).containsOnly(200);
        awaitEmail(email, NEW_DEVICE);
        assertQuietly(email, NEW_DEVICE, 1);
    }

    @Test
    void aFailedLoginRemembersNothingAndSendsNothing() throws Exception {
        String email = registeredUser();
        login(email, PASSWORD, null, "Firefox");

        MockHttpServletResponse wrong = login(email, "Wrong-passw0rd!", null, "Firefox")
                .andExpect(status().isUnauthorized()).andReturn().getResponse();

        assertThat(wrong.getCookie("deviceId")).isNull();
        assertThat(jdbc.queryForObject("select count(*) from known_devices where user_id = ?", Integer.class,
                user(email).getId())).isEqualTo(1);
        assertNoEmail(email, NEW_DEVICE);
    }

    @Test
    void loggingOutKeepsTheDeviceCookie() throws Exception {
        String email = registeredUser();
        ResultActions login = login(email, PASSWORD, null, "Firefox");

        MockHttpServletResponse logout = mvc.perform(post("/api/v1/auth/logout").cookie(refreshCookie(login)))
                .andExpect(status().isOk()).andReturn().getResponse();

        assertThat(logout.getHeaders(HttpHeaders.SET_COOKIE)).noneMatch(header -> header.startsWith("deviceId="));
    }

    /** Anyone can send any User-Agent: it must not become HTML in the email. */
    @Test
    void theDeviceNameIsEscaped() throws Exception {
        String email = registeredUser();
        login(email, PASSWORD, null, "Firefox");

        login(email, PASSWORD, null, "<a href=\"https://evil.example\">Click</a><script>x()</script>");

        String html = htmlBody(awaitEmail(email, NEW_DEVICE));
        assertThat(html).doesNotContain("<script>", "<a href=\"https://evil.example\"")
                .contains("&lt;script&gt;");
    }

    @Test
    void deletingTheAccountForgetsItsDevices() throws Exception {
        String email = registeredUser();
        String accessToken = accessToken(login(email, PASSWORD, null, "Firefox"));
        int userId = user(email).getId();

        requestAccountDeletion(accessToken).andExpect(status().isOk());
        confirmAccountDeletion(accessToken, deleteAccountOtp(email), PASSWORD).andExpect(status().isOk());

        assertThat(jdbc.queryForObject("select count(*) from known_devices where user_id = ?", Integer.class, userId)).isZero();
    }

    // ---- passwords -----------------------------------------------------------------

    @Test
    void aPasswordChangeIsEmailed() throws Exception {
        String email = registeredUser();
        String accessToken = accessToken(login(email, PASSWORD, null, "Firefox"));

        mvc.perform(as(accessToken, put("/api/v1/users/me/password")).with(from("198.51.100.4"))
                .header(HttpHeaders.USER_AGENT, "Laptop browser").contentType(MediaType.APPLICATION_JSON)
                .content("{\"currentPassword\": \"%s\", \"newPassword\": \"%s\"}".formatted(PASSWORD, NEW_PASSWORD)))
                .andExpect(status().isOk());

        MimeMessage message = awaitEmail(email, CHANGED);
        assertThat(htmlBody(message)).contains("198.51.100.4", "Laptop browser", "Forgot password")
                .doesNotContain(PASSWORD, NEW_PASSWORD);
        assertQuietly(email, CHANGED, 1);
    }

    @Test
    void aWrongCurrentPasswordSendsNothing() throws Exception {
        String email = registeredUser();
        String accessToken = accessToken(login(email, PASSWORD, null, "Firefox"));

        mvc.perform(as(accessToken, put("/api/v1/users/me/password")).contentType(MediaType.APPLICATION_JSON)
                .content("{\"currentPassword\": \"Wrong-passw0rd!\", \"newPassword\": \"%s\"}".formatted(NEW_PASSWORD)))
                .andExpect(status().isForbidden());

        assertNoEmail(email, CHANGED);
    }

    @Test
    void aPasswordResetIsEmailed() throws Exception {
        String email = registeredUser();
        requestPasswordReset(email).andExpect(status().isOk());
        String otp = passwordResetOtp(email);

        mvc.perform(post("/api/v1/auth/password-reset/confirm").with(from("198.51.100.7"))
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\": \"%s\", \"otp\": \"%s\", \"password\": \"%s\"}".formatted(email, otp, NEW_PASSWORD)))
                .andExpect(status().isOk());

        assertThat(htmlBody(awaitEmail(email, RESET))).contains("198.51.100.7").doesNotContain(otp, NEW_PASSWORD);
    }

    @Test
    void aWrongResetCodeSendsNothing() throws Exception {
        String email = registeredUser();
        requestPasswordReset(email).andExpect(status().isOk());

        confirmPasswordReset(email, wrongOtp(passwordResetOtp(email)), NEW_PASSWORD).andExpect(status().isBadRequest());

        assertNoEmail(email, RESET);
    }

    // ---- refresh tokens ------------------------------------------------------------

    @Test
    void aCopiedRefreshTokenIsEmailed() throws Exception {
        String email = registeredUser();
        Cookie stolen = refreshCookie(login(email, PASSWORD, null, "Firefox"));
        nextCookie(stolen);
        // Past the grace period for two tabs.
        jdbc.update("update refresh_tokens set used_at = used_at - interval 11 second where used_at is not null"
                + " and session_id in (select id from user_sessions where user_id = ?)", user(email).getId());

        refresh(stolen).andExpect(status().isUnauthorized());

        awaitEmail(email, ENDED);
        refresh(stolen).andExpect(status().isUnauthorized()); // its rows are gone: no second email
        assertQuietly(email, ENDED, 1);
    }

    @Test
    void anOrdinaryRefreshSendsNothing() throws Exception {
        String email = registeredUser();
        nextCookie(refreshCookie(login(email, PASSWORD, null, "Firefox")));

        assertNoEmail(email, ENDED);
    }

    // ---- helpers -------------------------------------------------------------------

    /** Registered and verified, not logged in yet. */
    private String registeredUser() throws Exception {
        String email = uniqueEmail();
        register(email, PASSWORD).andExpect(status().isOk());
        verifyEmail(verificationToken(email)).andExpect(status().isOk());
        return email;
    }

    private ResultActions login(String email, String password, Cookie device, String userAgent) throws Exception {
        return login(email, password, device, userAgent, "10.0.0." + (1 + (int) (Math.random() * 250)));
    }

    private ResultActions login(String email, String password, Cookie device, String userAgent, String ip)
            throws Exception {
        MockHttpServletRequestBuilder request = post("/api/v1/auth/login").with(from(ip))
                .header(HttpHeaders.USER_AGENT, userAgent)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\": \"%s\", \"password\": \"%s\"}".formatted(email, password));
        if (device != null)
            request.cookie(device);
        return mvc.perform(request);
    }

    private static Cookie deviceCookie(ResultActions login) throws Exception {
        Cookie cookie = login.andExpect(status().isOk()).andReturn().getResponse().getCookie("deviceId");
        assertThat(cookie).as("deviceId cookie").isNotNull();
        return cookie;
    }

    private static String setCookie(MockHttpServletResponse response, String name) {
        return response.getHeaders(HttpHeaders.SET_COOKIE).stream()
                .filter(header -> header.startsWith(name + "=")).findFirst().orElseThrow();
    }

    private void assertNoEmail(String to, String subject) throws Exception {
        assertQuietly(to, subject, 0);
    }

    /** After a while, exactly this many emails with this subject were sent. */
    private void assertQuietly(String to, String subject, int count) throws Exception {
        Thread.sleep(QUIET_MILLIS);
        assertThat(sentEmails(to, subject)).as(subject).hasSize(count);
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
