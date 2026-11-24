package com.authcore.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.transaction.IllegalTransactionStateException;

import com.authcore.auth.support.IntegrationTest;
import com.authcore.auth.token.OneTimeTokenService;
import com.authcore.auth.token.TokenPurpose;

/**
 * A1 and C1: codes and links are hashed, work once, expire, stop working after too many
 * wrong guesses, and can be requested again after a minute (H3).
 */
class OneTimeTokenTests extends IntegrationTest {
    private static final String NEW_PASSWORD = "N3w-Str0ng-Passw0rd!";

    @Autowired
    private OneTimeTokenService tokens;

    // ---- storage -------------------------------------------------------------------

    @Test
    void onlyHashesAreStored() throws Exception {
        String email = verifiedUser();
        String otp = requestReset(email);

        Map<String, Object> row = row(email, TokenPurpose.PASSWORD_RESET);

        assertThat((String) row.get("token_hash")).hasSize(64).doesNotContain(otp);
        assertThat(row.values()).extracting(String::valueOf).noneMatch(value -> value.contains(otp));
        assertThat((String) row(email, TokenPurpose.EMAIL_VERIFICATION).get("token_hash"))
                .doesNotContain(verificationToken(email));
    }

    @Test
    void deletingTheUserDeletesTheirTokens() throws Exception {
        String email = verifiedUser();
        requestReset(email);
        Integer id = user(email).getId();

        userRepository.deleteById(id);

        assertThat(jdbc.queryForObject("select count(*) from one_time_tokens where user_id = ?", Integer.class, id)).isZero();
    }

    // ---- guessing (C1) -------------------------------------------------------------

    /** On the old code any number of wrong guesses was allowed for an hour. */
    @Test
    void after5WrongGuessesEvenTheRightCodeIsRefused() throws Exception {
        String email = verifiedUser();
        String otp = requestReset(email);

        for (int i = 0; i < 5; i++)
            confirmReset(email, wrongOtp(otp)).andExpect(status().isBadRequest());

        confirmReset(email, otp)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_CODE"));
        login(email, PASSWORD).andExpect(status().isOk());
    }

    @Test
    void the5thGuessMayStillBeRight() throws Exception {
        String email = verifiedUser();
        String otp = requestReset(email);

        for (int i = 0; i < 4; i++)
            confirmReset(email, wrongOtp(otp)).andExpect(status().isBadRequest());

        confirmReset(email, otp).andExpect(status().isOk());
    }

    @Test
    void theWrongGuessesOfOneUserDontLockAnother() throws Exception {
        String attacked = verifiedUser();
        String other = verifiedUser();
        String otherOtp = requestReset(other);
        String otp = requestReset(attacked);

        for (int i = 0; i < 5; i++)
            confirmReset(attacked, wrongOtp(otp));

        confirmReset(other, otherOtp).andExpect(status().isOk());
    }

    @Test
    void aNewCodeStartsWithNoWrongGuesses() throws Exception {
        String email = verifiedUser();
        String otp = requestReset(email);
        for (int i = 0; i < 5; i++)
            confirmReset(email, wrongOtp(otp));

        confirmReset(email, requestAnotherReset(email)).andExpect(status().isOk());
    }

    /** A code is only good for its own user and purpose. */
    @Test
    void aCodeDoesntWorkForAnotherUserOrPurpose() throws Exception {
        String email = verifiedUser();
        String otp = requestReset(email);
        String other = verifiedUser();
        requestReset(other);

        confirmReset(other, otp).andExpect(status().isBadRequest());
        verifyEmail(otp).andExpect(status().isBadRequest());

        confirmReset(email, otp).andExpect(status().isOk());
    }

    // ---- single use and expiry -----------------------------------------------------

    @Test
    void aCodeWorksOnce() throws Exception {
        String email = verifiedUser();
        String otp = requestReset(email);

        confirmReset(email, otp).andExpect(status().isOk());
        confirmReset(email, otp).andExpect(status().isBadRequest());
    }

    @Test
    void anExpiredCodeIsRefusedLikeAWrongOne() throws Exception {
        String email = verifiedUser();
        String otp = requestReset(email);
        expire(email, TokenPurpose.PASSWORD_RESET);

        String expired = confirmReset(email, otp).andExpect(status().isBadRequest())
                .andReturn().getResponse().getContentAsString();
        String wrong = confirmReset(email, wrongOtp(otp)).andReturn().getResponse().getContentAsString();

        assertThat(expired).isEqualTo(wrong);
    }

    @Test
    void anExpiredLinkIsRefused() throws Exception {
        String email = uniqueEmail();
        register(email, PASSWORD);
        String token = verificationToken(email);
        expire(email, TokenPurpose.EMAIL_VERIFICATION);

        verifyEmail(token).andExpect(status().isBadRequest());
        assertThat(user(email).isEnabled()).isFalse();
    }

    @Test
    void eachPurposeHasItsOwnLifetime() throws Exception {
        String email = verifiedUser();
        requestReset(email);

        assertThat(lifetimeMinutes(email, TokenPurpose.EMAIL_VERIFICATION)).isEqualTo(24 * 60);
        assertThat(lifetimeMinutes(email, TokenPurpose.PASSWORD_RESET)).isEqualTo(15);
        assertThat(htmlBody(awaitEmail(email, "Password Reset"))).contains("valid for 15 minutes");
        assertThat(htmlBody(awaitEmail(email, "Verify Email"))).contains("valid for 24 hours");
    }

    // ---- resending (H3) ------------------------------------------------------------

    @Test
    void askingAgainWithinAMinuteSendsNothingAndKeepsTheCode() throws Exception {
        String email = verifiedUser();
        String otp = requestReset(email);

        requestPasswordReset(email).andExpect(status().isOk());

        Thread.sleep(300); // nothing is sent, so there is nothing to wait for
        assertThat(sentEmails(email, "Password Reset")).hasSize(1);
        confirmReset(email, otp).andExpect(status().isOk());
    }

    /** It used to take an hour (the old code had to expire first). */
    @Test
    void afterAMinuteANewCodeReplacesTheOldOne() throws Exception {
        String email = verifiedUser();
        String first = requestReset(email);

        String second = requestAnotherReset(email);

        if (!first.equals(second))
            confirmReset(email, first).andExpect(status().isBadRequest());
        confirmReset(email, second).andExpect(status().isOk());
    }

    @Test
    void aResentLinkReplacesTheOldOne() throws Exception {
        String email = uniqueEmail();
        register(email, PASSWORD);
        String first = verificationToken(email);
        waitOutTheCooldown(email, TokenPurpose.EMAIL_VERIFICATION);

        resendVerification(email).andExpect(status().isOk());
        awaitEmails(email, "Verify Email", 2);

        verifyEmail(first).andExpect(status().isBadRequest());
        verifyEmail(verificationToken(email)).andExpect(status().isOk());
    }

    /** Otherwise using up a code would be a way to send emails without a break. */
    @Test
    void theCooldownAlsoAppliesAfterACodeWasUsed() throws Exception {
        String email = verifiedUser();
        confirmReset(email, requestReset(email)).andExpect(status().isOk());

        requestPasswordReset(email).andExpect(status().isOk());

        Thread.sleep(300);
        assertThat(sentEmails(email, "Password Reset")).hasSize(1);
    }

    @Test
    void cooldownsOfDifferentPurposesAreSeparate() throws Exception {
        String email = verifiedUser(); // the verification email was sent a moment ago

        assertThat(requestReset(email)).isNotEmpty();
    }

    // ---- the service ---------------------------------------------------------------

    /** Without a transaction of the caller, the row lock would be gone before the token is used. */
    @Test
    void consumingNeedsATransaction() throws Exception {
        Integer id = user(verifiedUser()).getId();

        assertThatThrownBy(() -> tokens.consumeCode(id, "12345678", TokenPurpose.PASSWORD_RESET, user -> true))
                .isInstanceOf(IllegalTransactionStateException.class);
        assertThatThrownBy(() -> tokens.consumeLink("token", TokenPurpose.EMAIL_VERIFICATION))
                .isInstanceOf(IllegalTransactionStateException.class);
    }

    @Test
    void issuingForADeletedUserDoesNothing() {
        assertThat(tokens.issue(-1, TokenPurpose.PASSWORD_RESET)).isFalse();
    }

    // ---- helpers -------------------------------------------------------------------

    private String verifiedUser() throws Exception {
        String email = uniqueEmail();
        registerVerifiedUserAndLogin(email);
        return email;
    }

    /** Returns the code from the email. */
    private String requestReset(String email) throws Exception {
        requestPasswordReset(email).andExpect(status().isOk());
        return passwordResetOtp(email);
    }

    private String requestAnotherReset(String email) throws Exception {
        waitOutTheCooldown(email, TokenPurpose.PASSWORD_RESET);
        int sent = sentEmails(email, "Password Reset").size();
        requestPasswordReset(email).andExpect(status().isOk());
        awaitEmails(email, "Password Reset", sent + 1);
        return passwordResetOtp(email);
    }

    private ResultActions confirmReset(String email, String otp) throws Exception {
        return confirmPasswordReset(email, otp, NEW_PASSWORD);
    }

    private Map<String, Object> row(String email, TokenPurpose purpose) {
        return jdbc.queryForMap("select * from one_time_tokens where user_id = ? and purpose = ?",
                user(email).getId(), purpose.name());
    }

    private void expire(String email, TokenPurpose purpose) {
        jdbc.update("update one_time_tokens set expires_at = '2020-01-01' where user_id = ? and purpose = ?",
                user(email).getId(), purpose.name());
    }

    private int lifetimeMinutes(String email, TokenPurpose purpose) {
        return jdbc.queryForObject("select timestampdiff(minute, issued_at, expires_at) from one_time_tokens"
                + " where user_id = ? and purpose = ?", Integer.class, user(email).getId(), purpose.name());
    }
}
