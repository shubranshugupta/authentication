package com.authcore.auth;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.servlet.ResultActions;

import com.authcore.auth.support.IntegrationTest;

/**
 * M1: browsers on an allowed frontend origin can call the API, including PUT/DELETE
 * and with the refresh cookie. Before, the allowed origins were never read (field name
 * mismatch) and only GET and POST were allowed.
 */
class CorsTests extends IntegrationTest {
    private static final String FRONTEND = "http://localhost:3000";

    @Test
    void preflightFromTheFrontendIsAllowedWithCredentials() throws Exception {
        preflight(FRONTEND, "/api/v1/auth/login", "POST", "Content-Type")
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, FRONTEND))
                .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS, "true"))
                .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS, containsString("POST")));
    }

    @Test
    void putAndDeleteAreAllowedFromTheFrontend() throws Exception {
        preflight(FRONTEND, "/user/update-info", "PUT", "Authorization, Content-Type")
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS, containsString("PUT")));
        preflight(FRONTEND, "/user/delete", "DELETE", "Authorization")
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS, containsString("DELETE")));
    }

    @Test
    void viteDevServerOriginIsAllowedToo() throws Exception {
        preflight("http://localhost:5173", "/api/v1/auth/login", "POST", "Content-Type")
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, "http://localhost:5173"));
    }

    @Test
    void unknownOriginIsRejected() throws Exception {
        preflight("https://evil.example", "/api/v1/auth/login", "POST", "Content-Type")
                .andExpect(status().isForbidden())
                .andExpect(header().doesNotExist(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN));
    }

    @Test
    void actualResponsesCarryTheCorsHeaders() throws Exception {
        String accessToken = registerVerifiedUserAndLogin(uniqueEmail());

        mvc.perform(get("/user/get-info")
                .header(HttpHeaders.ORIGIN, FRONTEND)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, FRONTEND))
                .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS, "true"));
    }

    private ResultActions preflight(String origin, String path, String method, String headers) throws Exception {
        return mvc.perform(options(path)
                .header(HttpHeaders.ORIGIN, origin)
                .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, method)
                .header(HttpHeaders.ACCESS_CONTROL_REQUEST_HEADERS, headers));
    }
}
