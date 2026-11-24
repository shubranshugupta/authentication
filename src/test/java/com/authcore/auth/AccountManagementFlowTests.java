package com.authcore.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.ResultActions;

import com.authcore.auth.support.IntegrationTest;

import jakarta.servlet.http.Cookie;

/** Profile update, password reset, and account deletion. */
class AccountManagementFlowTests extends IntegrationTest {
    private static final String NEW_PASSWORD = "N3w-Str0ng-Passw0rd!";
    private static final String RESET_REQUESTED = "If an account with this email exists, a password reset email has been sent.";

    // ---- profile -------------------------------------------------------------------

    @Test
    void updatingTheProfileChangesTheName() throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);

        mvc.perform(put("/user/update-info")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"firstName": "janet", "lastName": "smith"}
                        """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.msg").value("User info updated successfully."));

        getProfile(accessToken)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.firstName").value("janet"))
                .andExpect(jsonPath("$.lastName").value("smith"));
        assertThat(user(email).getFirstName()).isEqualTo("janet");
    }

    /** The cached user used to be saved without its links, which deleted its refresh token. */
    @Test
    void updatingTheProfileKeepsTheUserLoggedIn() throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);
        Cookie refreshCookie = refreshCookie(email, PASSWORD);

        mvc.perform(put("/user/update-info")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"firstName": "janet", "lastName": "smith"}
                        """))
                .andExpect(status().isOk());

        refresh(refreshCookie).andExpect(status().isOk());
    }

    // ---- password reset ------------------------------------------------------------

    @Test
    void passwordResetWithTheEmailedOtpChangesThePassword() throws Exception {
        String email = uniqueEmail();
        registerVerifiedUserAndLogin(email);

        requestPasswordReset(email)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.msg").value(RESET_REQUESTED));
        String otp = passwordResetOtp(email);

        confirmPasswordReset(email, otp, NEW_PASSWORD)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.msg").value("Password reset successfully"));

        login(email, NEW_PASSWORD).andExpect(status().isOk());
        login(email, PASSWORD).andExpect(status().isUnauthorized());
    }

    /** Whoever knew the old password may hold a refresh token, so a reset ends the session. */
    @Test
    void passwordResetEndsTheSession() throws Exception {
        String email = uniqueEmail();
        registerVerifiedUserAndLogin(email);
        Cookie refreshCookie = refreshCookie(email, PASSWORD);

        requestPasswordReset(email).andExpect(status().isOk());
        confirmPasswordReset(email, passwordResetOtp(email), NEW_PASSWORD).andExpect(status().isOk());

        refresh(refreshCookie).andExpect(status().isUnauthorized());
    }

    @Test
    void passwordResetWithAWrongOtpReturns400AndKeepsTheOldPassword() throws Exception {
        String email = uniqueEmail();
        registerVerifiedUserAndLogin(email);
        requestPasswordReset(email).andExpect(status().isOk());

        confirmPasswordReset(email, wrongOtp(passwordResetOtp(email)), NEW_PASSWORD)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_CODE"));

        login(email, PASSWORD).andExpect(status().isOk());
    }

    @Test
    void passwordResetForAnUnverifiedAccountSendsNothing() throws Exception {
        String email = uniqueEmail();
        register(email, PASSWORD).andExpect(status().isOk());

        // Same answer as for a verified account (it used to say "Email not verified", H2).
        requestPasswordReset(email)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.msg").value(RESET_REQUESTED));
        awaitEmail(email, "Verify Email");
        assertThat(sentEmails(email, "Password Reset")).isEmpty();
    }

    // ---- account deletion ----------------------------------------------------------

    @Test
    void accountDeletionWithTheEmailedOtpDeletesTheUser() throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);

        requestAccountDeletion(accessToken)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.msg").value("Delete account email sent."));
        String otp = deleteAccountOtp(email);

        confirmAccountDeletion(accessToken, otp)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.msg").value("User deleted successfully."));

        assertThat(userRepository.findByEmail(email)).isEmpty();
        login(email, PASSWORD).andExpect(status().isUnauthorized());
    }

    @Test
    void theTokensOfADeletedAccountStopWorking() throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);
        Cookie refreshCookie = refreshCookie(email, PASSWORD);
        // Puts the refresh token in the Redis cache, where it used to outlive the account.
        refresh(refreshCookie).andExpect(status().isOk());

        requestAccountDeletion(accessToken).andExpect(status().isOk());
        confirmAccountDeletion(accessToken, deleteAccountOtp(email)).andExpect(status().isOk());

        getProfile(accessToken).andExpect(status().isUnauthorized());
        refresh(refreshCookie).andExpect(status().isUnauthorized());
    }

    @Test
    void accountDeletionWithAWrongOtpReturns400AndKeepsTheUser() throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);
        requestAccountDeletion(accessToken).andExpect(status().isOk());

        confirmAccountDeletion(accessToken, wrongOtp(deleteAccountOtp(email)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_CODE"));

        assertThat(userRepository.findByEmail(email)).isPresent();
    }

    // ---- helpers -------------------------------------------------------------------

    private ResultActions refresh(Cookie refreshCookie) throws Exception {
        return mvc.perform(post("/auth/refresh").cookie(refreshCookie));
    }

    private ResultActions requestPasswordReset(String email) throws Exception {
        return mvc.perform(post("/auth/reset-password").param("email", email));
    }

    private ResultActions confirmPasswordReset(String email, String otp, String newPassword) throws Exception {
        return mvc.perform(post("/auth/reset-password")
                .param("email", email)
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"otp": "%s", "password": "%s"}
                        """.formatted(otp, newPassword)));
    }

    private ResultActions requestAccountDeletion(String accessToken) throws Exception {
        return mvc.perform(delete("/user/delete").header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken));
    }

    private ResultActions confirmAccountDeletion(String accessToken, String otp) throws Exception {
        return mvc.perform(delete("/user/delete")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"otp": "%s"}
                        """.formatted(otp)));
    }
}
