package com.authcore.auth;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;

import com.authcore.auth.support.IntegrationTest;

/** Without GOOGLE_CLIENT_ID, as in the other tests, there is no Google sign-in. */
class GoogleSignInOffTests extends IntegrationTest {
    @Test
    void thereIsNothingToStartOrComeBackTo() throws Exception {
        mvc.perform(get("/api/v1/auth/oauth2/authorization/google")).andExpect(status().isNotFound());
        mvc.perform(get("/api/v1/auth/oauth2/callback/google").param("code", "x").param("state", "y"))
                .andExpect(status().isNotFound());
    }

    @Test
    void noCodeCanBeExchanged() throws Exception {
        postJson("/api/v1/auth/oauth2/exchange", "{\"code\": \"made-up\"}").andExpect(status().isBadRequest());
    }
}
