package com.authcore.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.MvcResult;

import com.authcore.auth.support.IntegrationTest;

import jakarta.servlet.http.Cookie;

/**
 * H2: nobody can find out whether an email is registered (or verified) from the
 * API's answers, and error responses never contain the submitted token.
 */
class AccountEnumerationTests extends IntegrationTest {
    private static final String NEW_PASSWORD = "N3w-Str0ng-Passw0rd!";

    // ---- login ---------------------------------------------------------------------

    @Test
    void unknownEmailAndWrongPasswordGetTheSameAnswer() throws Exception {
        String registered = uniqueEmail();
        registerVerifiedUserAndLogin(registered);

        MvcResult wrongPassword = login(registered, "Wrong-passw0rd!").andReturn();
        MvcResult unknownEmail = login(uniqueEmail(), "Wrong-passw0rd!").andReturn();

        assertSameAnswer(wrongPassword, unknownEmail, 401);
    }

    @Test
    void anUnverifiedAccountLooksLikeAnyOtherUntilThePasswordIsRight() throws Exception {
        String unverified = uniqueEmail();
        register(unverified, PASSWORD);

        // Wrong password: the same 401 as for an unknown email. (Spring used to check
        // "disabled" before the password, so any password revealed the account.)
        assertSameAnswer(login(unverified, "Wrong-passw0rd!").andReturn(),
                login(uniqueEmail(), "Wrong-passw0rd!").andReturn(), 401);

        // Right password: now it's fine to say the email needs verifying.
        login(unverified, PASSWORD).andExpect(status().isForbidden());
    }

    // ---- password reset ------------------------------------------------------------

    @Test
    void passwordResetRequestsAllGetTheSameAnswer() throws Exception {
        String verified = uniqueEmail();
        registerVerifiedUserAndLogin(verified);
        String unverified = uniqueEmail();
        register(unverified, PASSWORD);

        MvcResult forVerified = requestPasswordReset(verified).andReturn();
        MvcResult forUnverified = requestPasswordReset(unverified).andReturn();
        MvcResult forUnknown = requestPasswordReset(uniqueEmail()).andReturn();
        MvcResult whileOneIsActive = requestPasswordReset(verified).andReturn();

        assertSameAnswer(forVerified, forUnverified, 200);
        assertSameAnswer(forVerified, forUnknown, 200);
        assertSameAnswer(forVerified, whileOneIsActive, 200);
        // Only the verified account actually got a code.
        awaitEmail(verified, "Password Reset");
        assertThat(sentEmails(unverified, "Password Reset")).isEmpty();
    }

    @Test
    void confirmingAResetForAnUnknownEmailLooksLikeAWrongCode() throws Exception {
        String withCode = uniqueEmail();
        registerVerifiedUserAndLogin(withCode);
        requestPasswordReset(withCode);
        String withoutCode = uniqueEmail();
        registerVerifiedUserAndLogin(withoutCode);
        String unverified = uniqueEmail();
        register(unverified, PASSWORD);

        MvcResult wrongCode = confirmPasswordReset(withCode, wrongOtp(passwordResetOtp(withCode)), NEW_PASSWORD).andReturn();
        MvcResult noActiveCode = confirmPasswordReset(withoutCode, "12345678", NEW_PASSWORD).andReturn();
        MvcResult forUnverified = confirmPasswordReset(unverified, "12345678", NEW_PASSWORD).andReturn();
        MvcResult unknownEmail = confirmPasswordReset(uniqueEmail(), "12345678", NEW_PASSWORD).andReturn();

        assertSameAnswer(wrongCode, noActiveCode, 400);
        assertSameAnswer(wrongCode, forUnverified, 400);
        assertSameAnswer(wrongCode, unknownEmail, 400);
    }

    // ---- email verification --------------------------------------------------------

    @Test
    void verificationResendRequestsAllGetTheSameAnswer() throws Exception {
        String unverified = uniqueEmail();
        register(unverified, PASSWORD);
        String verified = uniqueEmail();
        registerVerifiedUserAndLogin(verified);

        MvcResult forUnverified = resendVerification(unverified).andReturn(); // a code is already active
        MvcResult forVerified = resendVerification(verified).andReturn();
        MvcResult forUnknown = resendVerification(uniqueEmail()).andReturn();

        assertSameAnswer(forUnverified, forVerified, 200);
        assertSameAnswer(forUnverified, forUnknown, 200);
    }

    /** The link says whose it is, so nothing in the request can be used to try out emails. */
    @Test
    void aUsedLinkLooksLikeAnInvalidOne() throws Exception {
        String email = uniqueEmail();
        registerVerifiedUserAndLogin(email);

        assertSameAnswer(verifyEmail(verificationToken(email)).andReturn(), verifyEmail("some-token").andReturn(), 400);
    }

    // ---- no tokens in error responses ----------------------------------------------

    @Test
    void errorResponsesDontEchoTheSubmittedToken() throws Exception {
        String fakeRefreshToken = "fake-refresh-token-1234567890";
        String fakeLinkToken = "fake-verification-token-1234567890";

        String refreshBody = refresh(new Cookie("refreshToken", fakeRefreshToken))
                .andExpect(status().isUnauthorized())
                .andReturn().getResponse().getContentAsString();
        String verifyBody = verifyEmail(fakeLinkToken)
                .andExpect(status().isBadRequest())
                .andReturn().getResponse().getContentAsString();

        assertThat(refreshBody).doesNotContain(fakeRefreshToken);
        assertThat(verifyBody).doesNotContain(fakeLinkToken);
    }

    // ---- helpers -------------------------------------------------------------------

    /** Same status and same body: the caller can't tell the two cases apart. */
    private static void assertSameAnswer(MvcResult a, MvcResult b, int expectedStatus) throws Exception {
        assertThat(a.getResponse().getStatus()).isEqualTo(expectedStatus);
        assertThat(b.getResponse().getStatus()).isEqualTo(expectedStatus);
        assertThat(withoutInstance(b.getResponse().getContentAsString()))
                .isEqualTo(withoutInstance(a.getResponse().getContentAsString()));
    }

    /** ProblemDetail includes the request path, which legitimately differs. */
    private static String withoutInstance(String body) {
        return body.replaceAll("\"instance\":\"[^\"]*\",?", "");
    }
}
