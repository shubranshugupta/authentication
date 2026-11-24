package com.authcore.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;

import com.authcore.auth.support.IntegrationTest;

import jakarta.servlet.http.Cookie;

/**
 * H2: nobody can find out whether an email is registered (or verified) from the
 * API's answers, and error responses never contain the submitted token.
 */
class AccountEnumerationTests extends IntegrationTest {

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

        MvcResult wrongCode = confirmPasswordReset(withCode, wrongOtp(passwordResetOtp(withCode))).andReturn();
        MvcResult noActiveCode = confirmPasswordReset(withoutCode, "12345678").andReturn();
        MvcResult forUnverified = confirmPasswordReset(unverified, "12345678").andReturn();
        MvcResult unknownEmail = confirmPasswordReset(uniqueEmail(), "12345678").andReturn();

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

    @Test
    void verificationLinksForUnknownOrVerifiedEmailsLookLikeInvalidLinks() throws Exception {
        String unverified = uniqueEmail();
        register(unverified, PASSWORD);
        String verified = uniqueEmail();
        registerVerifiedUserAndLogin(verified);

        MvcResult wrongToken = verifyEmail(unverified, "some-token").andReturn();
        MvcResult unknown = verifyEmail(uniqueEmail(), "some-token").andReturn();
        MvcResult alreadyVerified = verifyEmail(verified, "some-token").andReturn();

        assertSameAnswer(wrongToken, unknown, 400);
        assertSameAnswer(wrongToken, alreadyVerified, 400);
    }

    // ---- no tokens in error responses ----------------------------------------------

    @Test
    void errorResponsesDontEchoTheSubmittedToken() throws Exception {
        String unverified = uniqueEmail();
        register(unverified, PASSWORD);
        String fakeRefreshToken = "fake-refresh-token-1234567890";
        String fakeLinkToken = "fake-verification-token-1234567890";

        String refreshBody = mvc.perform(post("/auth/refresh").cookie(new Cookie("refreshToken", fakeRefreshToken)))
                .andExpect(status().isUnauthorized())
                .andReturn().getResponse().getContentAsString();
        String verifyBody = verifyEmail(unverified, fakeLinkToken)
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

    private ResultActions requestPasswordReset(String email) throws Exception {
        return mvc.perform(post("/auth/reset-password").param("email", email));
    }

    private ResultActions confirmPasswordReset(String email, String otp) throws Exception {
        return mvc.perform(post("/auth/reset-password").param("email", email)
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"otp": "%s", "password": "N3w-Str0ng-Passw0rd!"}
                        """.formatted(otp)));
    }

    private ResultActions resendVerification(String email) throws Exception {
        return mvc.perform(get("/auth/verify-email").param("email", email));
    }
}
