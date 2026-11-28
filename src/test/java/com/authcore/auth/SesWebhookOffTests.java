package com.authcore.auth;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;

import com.authcore.auth.support.IntegrationTest;

/** Without SES_SNS_TOPIC_ARN, as in the other tests, nothing is taken from SNS (M7e). */
class SesWebhookOffTests extends IntegrationTest {
    @Test
    void theEndpointIsOff() throws Exception {
        mvc.perform(post("/api/v1/webhooks/ses").contentType(MediaType.TEXT_PLAIN).content("{}"))
                .andExpect(status().isNotFound());
    }

    /** Public like the logins (SNS can't log in), so no access token is needed to reach it. */
    @Test
    void noAccessTokenIsNeeded() throws Exception {
        mvc.perform(post("/api/v1/webhooks/ses").header("Authorization", "Bearer not-a-token")
                .contentType(MediaType.TEXT_PLAIN).content("{}"))
                .andExpect(status().isNotFound());
    }
}
