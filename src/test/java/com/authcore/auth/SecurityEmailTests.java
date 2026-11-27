package com.authcore.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import com.authcore.auth.support.IntegrationTest;

import jakarta.mail.internet.MimeMessage;
import jakarta.servlet.http.Cookie;

/** F5: the owner hears of password changes and resets, and of a copied refresh token. */
class SecurityEmailTests extends IntegrationTest {
    private static final String CHANGED = "Your AuthCore password was changed";
    private static final String RESET = "Your AuthCore password was reset";
    private static final String ENDED = "You were logged out of AuthCore everywhere";
    private static final String NEW_PASSWORD = "N3w-Str0ng-Passw0rd!";
    /** Long enough for an email that was going to be sent to have been. */
    private static final long QUIET_MILLIS = 700;

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

    private void assertNoEmail(String to, String subject) throws Exception {
        assertQuietly(to, subject, 0);
    }

    /** After a while, exactly this many emails with this subject were sent. */
    private void assertQuietly(String to, String subject, int count) throws Exception {
        Thread.sleep(QUIET_MILLIS);
        assertThat(sentEmails(to, subject)).as(subject).hasSize(count);
    }

}
