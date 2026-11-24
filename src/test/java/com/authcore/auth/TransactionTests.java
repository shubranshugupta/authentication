package com.authcore.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;

import com.authcore.auth.support.IntegrationTest;

/** H5: a request either changes everything it should, or nothing. */
class TransactionTests extends IntegrationTest {

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
        mvc.perform(post("/auth/reset-password").param("email", email)).andExpect(status().isOk());
        String otp = passwordResetOtp(email);

        withoutTable("refresh_tokens", () -> confirmReset(email, otp, 500));

        login(email, PASSWORD).andExpect(status().isOk());
        confirmReset(email, otp, 200);
        login(email, "N3w-Str0ng-Passw0rd!").andExpect(status().isOk());
    }

    private void confirmReset(String email, String otp, int expectedStatus) throws Exception {
        mvc.perform(post("/auth/reset-password").param("email", email)
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"otp": "%s", "password": "N3w-Str0ng-Passw0rd!"}
                        """.formatted(otp))).andExpect(status().is(expectedStatus));
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
