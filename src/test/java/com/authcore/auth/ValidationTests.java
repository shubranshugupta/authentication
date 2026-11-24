package com.authcore.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
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
        mvc.perform(post("/auth/register").contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.firstName").exists())
                .andExpect(jsonPath("$.errors.email").exists())
                .andExpect(jsonPath("$.errors.password").exists());
    }

    @Test
    void malformedJsonReturns400() throws Exception {
        mvc.perform(post("/auth/register").contentType(MediaType.APPLICATION_JSON).content("{not json"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.msg").value("Malformed request body"));
    }

    // ---- other endpoints -----------------------------------------------------------

    @Test
    void loginRejectsABlankPassword() throws Exception {
        mvc.perform(post("/auth/login").contentType(MediaType.APPLICATION_JSON).content("""
                {"email": "%s", "password": ""}
                """.formatted(uniqueEmail())))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.password").exists());
    }

    @Test
    void passwordResetRejectsAWeakNewPasswordAndKeepsTheOtp() throws Exception {
        String email = uniqueEmail();
        registerVerifiedUserAndLogin(email);
        mvc.perform(post("/auth/reset-password").param("email", email)).andExpect(status().isOk());
        String otp = passwordResetOtp(email);

        mvc.perform(post("/auth/reset-password").param("email", email)
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"otp": %s, "password": "short"}
                        """.formatted(otp)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.password").value("must be at least 12 characters"));

        // Rejected before the OTP was checked, so it can still be used.
        assertThat(passwordResetOtp(email)).isEqualTo(otp);
        login(email, PASSWORD).andExpect(status().isOk());
    }

    @Test
    void passwordResetRejectsAMissingOtp() throws Exception {
        mvc.perform(post("/auth/reset-password").param("email", uniqueEmail())
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"password": "Twelve-char1"}
                        """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.otp").exists());
    }

    @Test
    void emailQueryParametersMustBeEmails() throws Exception {
        mvc.perform(get("/auth/verify-email").param("email", "nope"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.email").exists());
        mvc.perform(post("/auth/reset-password").param("email", ""))
                .andExpect(status().isBadRequest());
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

        mvc.perform(get("/auth/verify-email").param("email", mixed).param("token", verificationToken(lower)))
                .andExpect(status().isOk());
        login(lower.toUpperCase(), PASSWORD).andExpect(status().isOk());
        registerRaw("jane", lower, PASSWORD).andExpect(status().isConflict());
    }

    @Test
    void spacesAroundEmailsAreIgnored() throws Exception {
        String email = uniqueEmail();
        String padded = "  " + email + " ";

        registerRaw("jane", padded, PASSWORD).andExpect(status().isOk());
        assertThat(user(email).getEmail()).isEqualTo(email);

        mvc.perform(get("/auth/verify-email").param("email", padded).param("token", verificationToken(email)))
                .andExpect(status().isOk());
        login(padded, PASSWORD).andExpect(status().isOk());

        mvc.perform(post("/auth/reset-password").param("email", padded)).andExpect(status().isOk());
        mvc.perform(post("/auth/reset-password").param("email", padded)
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"otp": %s, "password": "N3w-Str0ng-Passw0rd!"}
                        """.formatted(passwordResetOtp(email))))
                .andExpect(status().isOk());
        login(email, "N3w-Str0ng-Passw0rd!").andExpect(status().isOk());
    }

    @Test
    void blankEmailsAreStillRejected() throws Exception {
        registerRaw("jane", "   ", PASSWORD)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.email").exists());
        mvc.perform(post("/auth/reset-password").param("email", "   ")).andExpect(status().isBadRequest());
    }

    @Test
    void anEmailThatIsNotAStringReturns400() throws Exception {
        for (String email : new String[] { "null", "{\"a\": 1}", "[\"a\"]" })
            mvc.perform(post("/auth/register").contentType(MediaType.APPLICATION_JSON).content("""
                    {"email": %s, "firstName": "jane", "password": "%s"}
                    """.formatted(email, PASSWORD))).andExpect(status().isBadRequest());
    }

    private ResultActions registerRaw(String firstName, String email, String password) throws Exception {
        return mvc.perform(post("/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"firstName": "%s", "lastName": "doe", "email": "%s", "password": "%s"}
                        """.formatted(firstName, email, password)));
    }
}
