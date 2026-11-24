package com.authcore.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;

import com.authcore.auth.support.IntegrationTest;

/** H5: a request either changes everything it should, or nothing. */
class TransactionTests extends IntegrationTest {
    private static final String NEW_PASSWORD = "N3w-Str0ng-Passw0rd!";

    /** It used to leave an account nobody had a link for, and the email was taken. */
    @Test
    void aRegistrationThatFailsHalfwayLeavesNoAccount() throws Exception {
        String email = uniqueEmail();

        withoutTable("one_time_tokens", () -> register(email, PASSWORD).andExpect(status().isInternalServerError()));

        assertThat(userRepository.findByEmail(email)).isEmpty();
        assertThat(sentEmails(email, "Verify Email")).isEmpty();
        register(email, PASSWORD).andExpect(status().isOk());
    }

    /** The code isn't used up, and the old password still works. */
    @Test
    void aPasswordResetThatFailsHalfwayChangesNothing() throws Exception {
        String email = uniqueEmail();
        registerVerifiedUserAndLogin(email);
        requestPasswordReset(email).andExpect(status().isOk());
        String otp = passwordResetOtp(email);

        withoutTable("refresh_tokens", () -> confirmPasswordReset(email, otp, NEW_PASSWORD).andExpect(status().isInternalServerError()));

        login(email, PASSWORD).andExpect(status().isOk());
        confirmPasswordReset(email, otp, NEW_PASSWORD).andExpect(status().isOk());
        login(email, NEW_PASSWORD).andExpect(status().isOk());
    }

    /** Makes every statement on this table fail in the meantime. */
    private void withoutTable(String table, Action action) throws Exception {
        jdbc.execute("rename table " + table + " to " + table + "_hidden");
        try {
            action.run();
        } finally {
            jdbc.execute("rename table " + table + "_hidden to " + table);
        }
    }

    private interface Action {
        void run() throws Exception;
    }
}
