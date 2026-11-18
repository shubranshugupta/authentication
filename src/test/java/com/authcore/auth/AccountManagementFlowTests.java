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

/** Profile update, password reset, and account deletion. */
class AccountManagementFlowTests extends IntegrationTest {
    private static final String NEW_PASSWORD = "N3w-Str0ng-Passw0rd!";

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

    // ---- password reset ------------------------------------------------------------

    @Test
    void passwordResetWithTheEmailedOtpChangesThePassword() throws Exception {
        String email = uniqueEmail();
        registerVerifiedUserAndLogin(email);

        requestPasswordReset(email)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.msg").value("Password reset email sent"));
        String otp = passwordResetOtp(email);
        assertThat(htmlBody(awaitEmail(email, "Password Reset"))).contains(otp);

        confirmPasswordReset(email, otp, NEW_PASSWORD)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.msg").value("Password reset successfully"));

        login(email, NEW_PASSWORD).andExpect(status().isOk());
        login(email, PASSWORD).andExpect(status().isUnauthorized());
        assertThat(passwordResetRepository.findByUser(user(email))).isEmpty();
    }

    @Test
    void passwordResetWithAWrongOtpReturns401AndKeepsTheOldPassword() throws Exception {
        String email = uniqueEmail();
        registerVerifiedUserAndLogin(email);
        requestPasswordReset(email).andExpect(status().isOk());

        confirmPasswordReset(email, wrongOtp(passwordResetOtp(email)), NEW_PASSWORD)
                .andExpect(status().isUnauthorized());

        login(email, PASSWORD).andExpect(status().isOk());
    }

    /** Current behaviour, recorded on purpose. H3 replaces this with a resend cooldown. */
    @Test
    void requestingASecondPasswordResetWhileOneIsActiveReturns409() throws Exception {
        String email = uniqueEmail();
        registerVerifiedUserAndLogin(email);
        requestPasswordReset(email).andExpect(status().isOk());

        requestPasswordReset(email).andExpect(status().isConflict());
    }

    @Test
    void passwordResetForAnUnverifiedAccountSendsNothing() throws Exception {
        String email = uniqueEmail();
        register(email, PASSWORD).andExpect(status().isOk());

        requestPasswordReset(email)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.msg").value("Email not verified"));
        assertThat(passwordResetRepository.findByUser(user(email))).isEmpty();
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
        assertThat(htmlBody(awaitEmail(email, "Delete Account"))).contains(otp);

        confirmAccountDeletion(accessToken, otp)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.msg").value("User deleted successfully."));

        assertThat(userRepository.findByEmail(email)).isEmpty();
        login(email, PASSWORD).andExpect(status().isNotFound());
    }

    @Test
    void accountDeletionWithAWrongOtpReturns401AndKeepsTheUser() throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);
        requestAccountDeletion(accessToken).andExpect(status().isOk());

        confirmAccountDeletion(accessToken, wrongOtp(deleteAccountOtp(email)))
                .andExpect(status().isUnauthorized());

        assertThat(userRepository.findByEmail(email)).isPresent();
    }

    // ---- helpers -------------------------------------------------------------------

    private ResultActions requestPasswordReset(String email) throws Exception {
        return mvc.perform(post("/auth/reset-password").param("email", email));
    }

    private ResultActions confirmPasswordReset(String email, String otp, String newPassword) throws Exception {
        return mvc.perform(post("/auth/reset-password")
                .param("email", email)
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"otp": %s, "password": "%s"}
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
                        {"otp": %s}
                        """.formatted(otp)));
    }
}
