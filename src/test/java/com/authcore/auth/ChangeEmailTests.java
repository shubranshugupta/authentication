package com.authcore.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.ResultActions;

import com.authcore.auth.support.IntegrationTest;
import com.authcore.auth.token.TokenPurpose;

import jakarta.servlet.http.Cookie;

/**
 * F5: a logged-in user changes their email. A code confirms the new address; the old one
 * gets a link that changes it back for 7 days.
 */
class ChangeEmailTests extends IntegrationTest {
    private static final String CODE_SUBJECT = "Confirm your new AuthCore email";
    private static final String UNDO_SUBJECT = "Your AuthCore email was changed";
    private static final String NEW_PASSWORD = "N3w-Str0ng-Passw0rd!";
    private static final Pattern UNDO_TOKEN = Pattern.compile("undo-email-change\\?token=([A-Za-z0-9_-]{43})");
    /** Long enough for an email that was going to be sent to have been. */
    private static final long QUIET_MILLIS = 700;

    // ---- asking for a code ---------------------------------------------------------

    @Test
    void theCodeGoesToTheNewAddressAndNothingChangesYet() throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);
        String newEmail = uniqueEmail();

        requestChange(accessToken, PASSWORD, newEmail).andExpect(status().isOk());

        assertThat(htmlBody(awaitEmail(newEmail, CODE_SUBJECT))).contains("valid for 15 minutes");
        getProfile(accessToken).andExpect(jsonPath("$.email").value(email));
        login(email, PASSWORD).andExpect(status().isOk());
    }

    @Test
    void theNewAddressIsNormalized() throws Exception {
        String accessToken = registerVerifiedUserAndLogin(uniqueEmail());
        String newEmail = uniqueEmail();

        requestChange(accessToken, PASSWORD, "  " + newEmail.toUpperCase() + " ").andExpect(status().isOk());
        confirmChange(accessToken, emailChangeOtp(newEmail)).andExpect(status().isOk());

        getProfile(accessToken).andExpect(jsonPath("$.email").value(newEmail));
    }

    @Test
    void aWrongPasswordSendsNothing() throws Exception {
        String accessToken = registerVerifiedUserAndLogin(uniqueEmail());
        String newEmail = uniqueEmail();

        requestChange(accessToken, "Wrong-passw0rd!", newEmail)
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("WRONG_PASSWORD"));

        assertNoEmail(newEmail, CODE_SUBJECT);
    }

    @Test
    void theCurrentAddressIsRefused() throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);

        requestChange(accessToken, PASSWORD, email.toUpperCase())
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("EMAIL_CHANGE_REFUSED"));
    }

    @Test
    void anotherAccountsAddressIsRefusedAndSentNothing() throws Exception {
        String accessToken = registerVerifiedUserAndLogin(uniqueEmail());
        String other = uniqueEmail();
        registerVerifiedUserAndLogin(other);

        requestChange(accessToken, PASSWORD, other)
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("USER_ALREADY_EXISTS"));

        assertNoEmail(other, CODE_SUBJECT);
    }

    @Test
    void anInvalidAddressIsRefused() throws Exception {
        String accessToken = registerVerifiedUserAndLogin(uniqueEmail());

        requestChange(accessToken, PASSWORD, "not-an-email")
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_INPUT"));
    }

    @Test
    void anotherCodeWithinAMinuteIsRefused() throws Exception {
        String accessToken = registerVerifiedUserAndLogin(uniqueEmail());
        requestChange(accessToken, PASSWORD, uniqueEmail()).andExpect(status().isOk());

        requestChange(accessToken, PASSWORD, uniqueEmail())
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("TOKEN_ALREADY_EXISTS"));
    }

    @Test
    void aNewCodeReplacesTheOldOne() throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);
        String first = uniqueEmail();
        String second = uniqueEmail();
        requestChange(accessToken, PASSWORD, first).andExpect(status().isOk());
        String firstCode = emailChangeOtp(first);
        waitOutTheCooldown(email, TokenPurpose.EMAIL_CHANGE);
        requestChange(accessToken, PASSWORD, second).andExpect(status().isOk());
        String secondCode = emailChangeOtp(second);

        if (!firstCode.equals(secondCode))
            confirmChange(accessToken, firstCode).andExpect(status().isBadRequest());
        confirmChange(accessToken, secondCode).andExpect(status().isOk());

        getProfile(accessToken).andExpect(jsonPath("$.email").value(second));
    }

    @Test
    void requestsAreLimitedSoThatTheyCantBeUsedToSendMailToAnybody() throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);

        for (int i = 0; i < 10; i++) {
            waitOutTheCooldown(email, TokenPurpose.EMAIL_CHANGE);
            requestChange(accessToken, PASSWORD, uniqueEmail()).andExpect(status().isOk());
        }

        waitOutTheCooldown(email, TokenPurpose.EMAIL_CHANGE);
        String newEmail = uniqueEmail();
        requestChange(accessToken, PASSWORD, newEmail).andExpect(status().isTooManyRequests());
        assertNoEmail(newEmail, CODE_SUBJECT);
    }

    // ---- confirming it -------------------------------------------------------------

    @Test
    void theCodeChangesTheEmailAndEveryDeviceStaysLoggedIn() throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);
        ResultActions phone = login(email, PASSWORD);
        String newEmail = uniqueEmail();

        change(accessToken, newEmail);

        getProfile(accessToken).andExpect(jsonPath("$.email").value(newEmail));
        login(newEmail, PASSWORD).andExpect(status().isOk());
        login(email, PASSWORD).andExpect(status().isUnauthorized());
        getProfile(accessToken(phone)).andExpect(status().isOk());
        refresh(refreshCookie(phone)).andExpect(status().isOk());
    }

    @Test
    void theOldAddressGetsAnUndoLinkWithWhenAndWhere() throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);
        String newEmail = uniqueEmail();
        requestChange(accessToken, PASSWORD, newEmail).andExpect(status().isOk());

        mvc.perform(as(accessToken, post("/api/v1/users/me/email/confirm")).with(from("198.51.100.9"))
                .header(HttpHeaders.USER_AGENT, "<b>Phone</b>").contentType(MediaType.APPLICATION_JSON)
                .content("{\"otp\": \"%s\"}".formatted(emailChangeOtp(newEmail))))
                .andExpect(status().isOk());

        String html = htmlBody(awaitEmail(email, UNDO_SUBJECT));
        assertThat(html).contains("u***@example.com", "198.51.100.9", "&lt;b&gt;Phone&lt;/b&gt;", "within 7 days")
                .containsPattern(UNDO_TOKEN)
                // Masked: whoever reads the old inbox can't write to the new one.
                .doesNotContain(newEmail, "<b>Phone</b>");
        assertNoEmail(newEmail, UNDO_SUBJECT);
    }

    @Test
    void aWrongCodeChangesNothingAndFiveUseItUp() throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);
        String newEmail = uniqueEmail();
        requestChange(accessToken, PASSWORD, newEmail).andExpect(status().isOk());
        String code = emailChangeOtp(newEmail);

        for (int i = 0; i < 5; i++)
            confirmChange(accessToken, wrongOtp(code))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.code").value("INVALID_CODE"));
        confirmChange(accessToken, code).andExpect(status().isBadRequest());

        getProfile(accessToken).andExpect(jsonPath("$.email").value(email));
        assertNoEmail(email, UNDO_SUBJECT);
    }

    @Test
    void aCodeOnlyWorksForItsOwnAccount() throws Exception {
        String accessToken = registerVerifiedUserAndLogin(uniqueEmail());
        String otherEmail = uniqueEmail();
        String other = registerVerifiedUserAndLogin(otherEmail);
        String newEmail = uniqueEmail();
        requestChange(accessToken, PASSWORD, newEmail).andExpect(status().isOk());

        confirmChange(other, emailChangeOtp(newEmail)).andExpect(status().isBadRequest());

        getProfile(other).andExpect(jsonPath("$.email").value(otherEmail));
    }

    @Test
    void anAddressTakenMeanwhileIsRefused() throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);
        String newEmail = uniqueEmail();
        requestChange(accessToken, PASSWORD, newEmail).andExpect(status().isOk());
        String code = emailChangeOtp(newEmail);
        register(newEmail, PASSWORD).andExpect(status().isOk());

        confirmChange(accessToken, code)
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("USER_ALREADY_EXISTS"));

        getProfile(accessToken).andExpect(jsonPath("$.email").value(email));
    }

    @Test
    void theSameCodeSentTwiceAtOnceChangesTheEmailOnce() throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);
        String newEmail = uniqueEmail();
        requestChange(accessToken, PASSWORD, newEmail).andExpect(status().isOk());
        String code = emailChangeOtp(newEmail);

        List<Integer> statuses = allAtOnce(4, () -> confirmChange(accessToken, code).andReturn().getResponse().getStatus());

        assertThat(statuses).containsOnlyOnce(200).containsOnly(200, 400);
        assertQuietly(email, UNDO_SUBJECT, 1);
    }

    @Test
    void aResetCodeSentToTheOldAddressStopsWorking() throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);
        requestPasswordReset(email).andExpect(status().isOk());
        String resetCode = passwordResetOtp(email);
        String newEmail = uniqueEmail();

        change(accessToken, newEmail);

        confirmPasswordReset(newEmail, resetCode, NEW_PASSWORD).andExpect(status().isBadRequest());
        login(newEmail, PASSWORD).andExpect(status().isOk());
    }

    // ---- while the undo link works ---------------------------------------------------

    @Test
    void theEmailCantChangeAgainUntilTheUndoLinkExpires() throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);
        String newEmail = uniqueEmail();
        change(accessToken, newEmail);

        requestChange(accessToken, PASSWORD, uniqueEmail())
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("EMAIL_CHANGE_REFUSED"));

        expireUndoLink(newEmail);
        waitOutTheCooldown(newEmail, TokenPurpose.EMAIL_CHANGE);
        requestChange(accessToken, PASSWORD, uniqueEmail()).andExpect(status().isOk());
    }

    @Test
    void nobodyElseCanTakeTheOldAddressUntilTheUndoLinkExpires() throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);
        String newEmail = uniqueEmail();
        change(accessToken, newEmail);
        String other = registerVerifiedUserAndLogin(uniqueEmail());

        register(email, PASSWORD).andExpect(status().isConflict());
        requestChange(other, PASSWORD, email)
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("USER_ALREADY_EXISTS"));

        expireUndoLink(newEmail);
        register(email, PASSWORD).andExpect(status().isOk());
    }

    // ---- undoing it ------------------------------------------------------------------

    @Test
    void theUndoLinkChangesTheEmailBackSetsAPasswordAndLogsOutEverywhere() throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);
        Cookie refreshCookie = refreshCookie(email, PASSWORD);
        String newEmail = uniqueEmail();
        change(accessToken, newEmail);
        // Whoever changed it logs in again.
        String attacker = accessToken(newEmail, PASSWORD);

        undo(undoEmailChangeToken(email), NEW_PASSWORD).andExpect(status().isOk());

        getProfile(accessToken).andExpect(status().isUnauthorized());
        getProfile(attacker).andExpect(status().isUnauthorized());
        refresh(refreshCookie).andExpect(status().isUnauthorized());
        login(newEmail, PASSWORD).andExpect(status().isUnauthorized());
        login(email, PASSWORD).andExpect(status().isUnauthorized());
        getProfile(accessToken(email, NEW_PASSWORD)).andExpect(jsonPath("$.email").value(email));
    }

    @Test
    void theUndoLinkWorksOnce() throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);
        change(accessToken, uniqueEmail());
        String token = undoEmailChangeToken(email);

        undo(token, NEW_PASSWORD).andExpect(status().isOk());

        undo(token, "An0ther-Str0ng-Passw0rd!")
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_CODE"));
        login(email, NEW_PASSWORD).andExpect(status().isOk());
    }

    @Test
    void anExpiredOrMadeUpUndoLinkDoesNothing() throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);
        String newEmail = uniqueEmail();
        change(accessToken, newEmail);
        String token = undoEmailChangeToken(email);
        expireUndoLink(newEmail);

        undo(token, NEW_PASSWORD).andExpect(status().isBadRequest());
        undo("A".repeat(43), NEW_PASSWORD).andExpect(status().isBadRequest());

        login(newEmail, PASSWORD).andExpect(status().isOk());
    }

    @Test
    void aWeakPasswordIsRefusedAndTheLinkStillWorks() throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);
        change(accessToken, uniqueEmail());
        String token = undoEmailChangeToken(email);

        undo(token, "short").andExpect(status().isBadRequest()).andExpect(jsonPath("$.code").value("INVALID_INPUT"));

        undo(token, NEW_PASSWORD).andExpect(status().isOk());
    }

    @Test
    void aResetCodeSentToTheNewAddressStopsWorkingAfterTheUndo() throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);
        String newEmail = uniqueEmail();
        change(accessToken, newEmail);
        requestPasswordReset(newEmail).andExpect(status().isOk());
        String resetCode = passwordResetOtp(newEmail);

        undo(undoEmailChangeToken(email), NEW_PASSWORD).andExpect(status().isOk());

        confirmPasswordReset(email, resetCode, "An0ther-Str0ng-Passw0rd!").andExpect(status().isBadRequest());
        login(email, NEW_PASSWORD).andExpect(status().isOk());
    }

    @Test
    void afterTheUndoTheEmailCanChangeAgain() throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);
        String newEmail = uniqueEmail();
        change(accessToken, newEmail);
        undo(undoEmailChangeToken(email), NEW_PASSWORD).andExpect(status().isOk());
        String again = accessToken(email, NEW_PASSWORD);

        // The address it had is free again, too.
        requestChange(again, NEW_PASSWORD, newEmail).andExpect(status().isOk());
    }

    @Test
    void deletingTheAccountFreesTheOldAddress() throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);
        String newEmail = uniqueEmail();
        change(accessToken, newEmail);

        requestAccountDeletion(accessToken).andExpect(status().isOk());
        confirmAccountDeletion(accessToken, deleteAccountOtp(newEmail), PASSWORD).andExpect(status().isOk());

        register(email, PASSWORD).andExpect(status().isOk());
    }

    // ---- helpers -------------------------------------------------------------------

    private ResultActions requestChange(String accessToken, String password, String newEmail) throws Exception {
        return mvc.perform(as(accessToken, post("/api/v1/users/me/email")).contentType(MediaType.APPLICATION_JSON)
                .content("{\"currentPassword\": \"%s\", \"newEmail\": \"%s\"}".formatted(password, newEmail)));
    }

    private ResultActions confirmChange(String accessToken, String code) throws Exception {
        return mvc.perform(as(accessToken, post("/api/v1/users/me/email/confirm"))
                .contentType(MediaType.APPLICATION_JSON).content("{\"otp\": \"%s\"}".formatted(code)));
    }

    private ResultActions undo(String token, String password) throws Exception {
        return postJson("/api/v1/auth/email-change/undo",
                "{\"token\": \"%s\", \"password\": \"%s\"}".formatted(token, password));
    }

    /** Changes the email all the way. */
    private void change(String accessToken, String newEmail) throws Exception {
        requestChange(accessToken, PASSWORD, newEmail).andExpect(status().isOk());
        confirmChange(accessToken, emailChangeOtp(newEmail)).andExpect(status().isOk());
    }

    /** As if it had been sent 8 days ago. */
    private void expireUndoLink(String email) {
        jdbc.update("update one_time_tokens set expires_at = expires_at - interval 8 day, issued_at = issued_at"
                + " - interval 8 day where purpose = 'EMAIL_CHANGE_UNDO' and user_id = ?", user(email).getId());
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
