package com.authcore.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.ResultActions;

import com.authcore.auth.support.IntegrationTest;

/**
 * H1: invalid input gets 400 with per-field errors (it used to be accepted, or fail
 * with 500), new passwords follow the policy, and emails are normalized.
 */
class ValidationTests extends IntegrationTest {

    // ---- registration --------------------------------------------------------------

    @Test
    void registrationRejectsAnInvalidEmail() throws Exception {
        registerRaw("jane", "not-an-email", PASSWORD)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.msg").value("Invalid input"))
                .andExpect(jsonPath("$.errors.email").exists());
    }

    @Test
    void registrationRejectsAPasswordShorterThan12Characters() throws Exception {
        String email = uniqueEmail();

        registerRaw("jane", email, "Short-pass1")   // 11 characters
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.password").value("must be at least 12 characters"));
        assertThat(userRepository.findByEmail(email)).isEmpty();

        registerRaw("jane", email, "Twelve-char1").andExpect(status().isOk());
    }

    @Test
    void registrationRejectsAPasswordLongerThan72Bytes() throws Exception {
        registerRaw("jane", uniqueEmail(), "é".repeat(40))   // 40 characters, 80 bytes
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.password").value(org.hamcrest.Matchers.startsWith("must be at most 72 bytes")));
    }

    @Test
    void registrationRejectsMissingFieldsInsteadOfFailingWith500() throws Exception {
        mvc.perform(post("/api/v1/auth/register").contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.firstName").exists())
                .andExpect(jsonPath("$.errors.email").exists())
                .andExpect(jsonPath("$.errors.password").exists());
    }

    @Test
    void malformedJsonReturns400() throws Exception {
        mvc.perform(post("/api/v1/auth/register").contentType(MediaType.APPLICATION_JSON).content("{not json"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.msg").value("Malformed request body"));
    }

    // ---- other endpoints -----------------------------------------------------------

    @Test
    void loginRejectsABlankPassword() throws Exception {
        mvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON).content("""
                {"email": "%s", "password": ""}
                """.formatted(uniqueEmail())))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.password").exists());
    }

    @Test
    void passwordResetRejectsAWeakNewPasswordAndKeepsTheOtp() throws Exception {
        String email = uniqueEmail();
        registerVerifiedUserAndLogin(email);
        requestPasswordReset(email).andExpect(status().isOk());
        String otp = passwordResetOtp(email);

        confirmPasswordReset(email, otp, "short")
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.password").value("must be at least 12 characters"));

        // Rejected before the OTP was checked, so it can still be used.
        login(email, PASSWORD).andExpect(status().isOk());
        confirmPasswordReset(email, otp, "Twelve-char1").andExpect(status().isOk());
    }

    @Test
    void passwordResetRejectsMissingFields() throws Exception {
        postJson("/api/v1/auth/password-reset/confirm", "{}")
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.email").exists())
                .andExpect(jsonPath("$.errors.otp").exists())
                .andExpect(jsonPath("$.errors.password").exists());
    }

    /** Answered before any account is looked up, and without counting a guess. */
    @Test
    void passwordResetRejectsAnOtpThatIsNot8Digits() throws Exception {
        for (String otp : new String[] { "1234567", "123456789", "1234567a", "", "\u0661\u0662\u0663\u0664\u0665\u0666\u0667\u0668" })
            confirmPasswordReset(uniqueEmail(), otp, "Twelve-char1")
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.errors.otp").exists());
    }

    @Test
    void emailRequestsNeedAnEmail() throws Exception {
        for (String path : new String[] { "/api/v1/auth/email-verification", "/api/v1/auth/password-reset" })
            for (String body : new String[] { "{}", "{\"email\": \"nope\"}", "{\"email\": \"\"}", "{\"email\": \"   \"}", "{\"email\": null}" })
                postJson(path, body)
                        .andExpect(status().isBadRequest())
                        .andExpect(jsonPath("$.errors.email").exists());
    }

    @Test
    void verificationNeedsAToken() throws Exception {
        for (String body : new String[] { "{}", "{\"token\": \" \"}", "{\"token\": \"" + "x".repeat(201) + "\"}" })
            postJson("/api/v1/auth/email-verification/confirm", body)
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.errors.token").exists());
    }

    @Test
    void profileUpdateRejectsABlankFirstName() throws Exception {
        String accessToken = registerVerifiedUserAndLogin(uniqueEmail());

        mvc.perform(put("/user/update-info")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"firstName": "  ", "lastName": "doe"}
                        """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.firstName").exists());
    }

    // ---- email normalization -------------------------------------------------------

    @Test
    void emailsAreStoredAndMatchedInLowercase() throws Exception {
        String lower = uniqueEmail();
        String mixed = lower.toUpperCase().replace("@EXAMPLE.COM", "@Example.COM");

        registerRaw("jane", mixed, PASSWORD).andExpect(status().isOk());
        assertThat(user(lower).getEmail()).isEqualTo(lower);

        verifyEmail(verificationToken(lower)).andExpect(status().isOk());
        login(lower.toUpperCase(), PASSWORD).andExpect(status().isOk());
        registerRaw("jane", lower, PASSWORD).andExpect(status().isConflict());
    }

    @Test
    void spacesAroundEmailsAreIgnored() throws Exception {
        String email = uniqueEmail();
        String padded = "  " + email + " ";

        registerRaw("jane", padded, PASSWORD).andExpect(status().isOk());
        assertThat(user(email).getEmail()).isEqualTo(email);

        verifyEmail(verificationToken(email)).andExpect(status().isOk());
        login(padded, PASSWORD).andExpect(status().isOk());

        requestPasswordReset(padded).andExpect(status().isOk());
        confirmPasswordReset(padded, passwordResetOtp(email), "N3w-Str0ng-Passw0rd!").andExpect(status().isOk());
        login(email, "N3w-Str0ng-Passw0rd!").andExpect(status().isOk());
    }

    @Test
    void blankEmailsAreStillRejected() throws Exception {
        registerRaw("jane", "   ", PASSWORD)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.email").exists());
    }

    @Test
    void anEmailThatIsNotAStringReturns400() throws Exception {
        for (String email : new String[] { "null", "{\"a\": 1}", "[\"a\"]" })
            mvc.perform(post("/api/v1/auth/register").contentType(MediaType.APPLICATION_JSON).content("""
                    {"email": %s, "firstName": "jane", "password": "%s"}
                    """.formatted(email, PASSWORD))).andExpect(status().isBadRequest());
    }

    private ResultActions registerRaw(String firstName, String email, String password) throws Exception {
        return mvc.perform(post("/api/v1/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"firstName": "%s", "lastName": "doe", "email": "%s", "password": "%s"}
                        """.formatted(firstName, email, password)));
    }
}
