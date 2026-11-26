package com.authcore.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;

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

        updateProfile(accessToken, """
                {"firstName": "janet", "lastName": "smith"}
                """)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.msg").value("User info updated successfully."));

        getProfile(accessToken)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.firstName").value("janet"))
                .andExpect(jsonPath("$.lastName").value("smith"));
        assertThat(user(email).getFirstName()).isEqualTo("janet");
    }

    /** PATCH: what is left out stays as it was. */
    @Test
    void updatingOneNameKeepsTheOther() throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);

        updateProfile(accessToken, "{\"firstName\": \"janet\"}").andExpect(status().isOk());
        getProfile(accessToken)
                .andExpect(jsonPath("$.firstName").value("janet"))
                .andExpect(jsonPath("$.lastName").value("doe"));

        updateProfile(accessToken, "{\"lastName\": \"smith\"}").andExpect(status().isOk());
        getProfile(accessToken)
                .andExpect(jsonPath("$.firstName").value("janet"))
                .andExpect(jsonPath("$.lastName").value("smith"));

        updateProfile(accessToken, "{}").andExpect(status().isOk());
        assertThat(user(email).getFirstName()).isEqualTo("janet");

        updateProfile(accessToken, "{\"lastName\": \"\"}").andExpect(status().isOk());
        assertThat(user(email).getLastName()).isNull();
    }

    /** The cached user used to be saved without its links, which deleted its refresh token. */
    @Test
    void updatingTheProfileKeepsTheUserLoggedIn() throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);
        Cookie refreshCookie = refreshCookie(email, PASSWORD);

        updateProfile(accessToken, """
                {"firstName": "janet", "lastName": "smith"}
                """)
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

        confirmAccountDeletion(accessToken, otp, PASSWORD)
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
        refreshCookie = nextCookie(refreshCookie);

        requestAccountDeletion(accessToken).andExpect(status().isOk());
        confirmAccountDeletion(accessToken, deleteAccountOtp(email), PASSWORD).andExpect(status().isOk());

        getProfile(accessToken).andExpect(status().isUnauthorized());
        refresh(refreshCookie).andExpect(status().isUnauthorized());
    }

    @Test
    void accountDeletionWithAWrongOtpReturns400AndKeepsTheUser() throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);
        requestAccountDeletion(accessToken).andExpect(status().isOk());

        confirmAccountDeletion(accessToken, wrongOtp(deleteAccountOtp(email)), PASSWORD)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_CODE"));

        assertThat(userRepository.findByEmail(email)).isPresent();
    }

    /** H8: a session and access to the inbox aren't enough. */
    @Test
    void accountDeletionNeedsThePassword() throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);
        requestAccountDeletion(accessToken).andExpect(status().isOk());
        String otp = deleteAccountOtp(email);

        confirmAccountDeletion(accessToken, otp, "wrong-password")
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_CODE"));
        assertThat(userRepository.findByEmail(email)).isPresent();

        confirmAccountDeletion(accessToken, otp, PASSWORD).andExpect(status().isOk());
        assertThat(userRepository.findByEmail(email)).isEmpty();
    }

    /** Otherwise this would be a place to guess passwords without a limit. */
    @Test
    void wrongPasswordsUseUpTheCode() throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);
        requestAccountDeletion(accessToken).andExpect(status().isOk());
        String otp = deleteAccountOtp(email);

        for (int i = 0; i < 5; i++)
            confirmAccountDeletion(accessToken, otp, "wrong-password").andExpect(status().isBadRequest());

        confirmAccountDeletion(accessToken, otp, PASSWORD).andExpect(status().isBadRequest());
        assertThat(userRepository.findByEmail(email)).isPresent();
    }

    @Test
    void aWrongCodeAndAWrongPasswordGetTheSameAnswer() throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);
        requestAccountDeletion(accessToken).andExpect(status().isOk());
        String otp = deleteAccountOtp(email);

        String wrongCode = confirmAccountDeletion(accessToken, wrongOtp(otp), PASSWORD)
                .andReturn().getResponse().getContentAsString();
        String wrongPassword = confirmAccountDeletion(accessToken, otp, "wrong-password")
                .andReturn().getResponse().getContentAsString();

        assertThat(wrongCode).isEqualTo(wrongPassword);
    }

    @Test
    void accountDeletionNeedsALogin() throws Exception {
        postJson("/api/v1/users/me/deletion", "").andExpect(status().isUnauthorized());
        postJson("/api/v1/users/me/deletion/confirm", "{}").andExpect(status().isUnauthorized());
    }
}
