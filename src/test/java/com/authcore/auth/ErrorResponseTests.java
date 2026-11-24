package com.authcore.auth;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Instant;
import java.util.Date;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import com.authcore.auth.config.AdminBootstrap;
import com.authcore.auth.support.IntegrationTest;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

/** A2/M6: every error is a ProblemDetail with a stable code, wherever it happens. */
class ErrorResponseTests extends IntegrationTest {

    @Autowired
    private AdminBootstrap adminBootstrap;

    @Value("${auth.token.secret-key}")
    private String jwtSecret;

    // ---- input ---------------------------------------------------------------------

    @Test
    void invalidFields() throws Exception {
        expect(400, "INVALID_INPUT", json(post("/auth/register"), "{}"))
                .andExpect(jsonPath("$.errors.email").exists())
                .andExpect(jsonPath("$.errors.password").exists());
    }

    @Test
    void invalidQueryParameter() throws Exception {
        expect(400, "INVALID_INPUT", post("/auth/reset-password").param("email", "not-an-email"))
                .andExpect(jsonPath("$.errors.email").exists());
    }

    @Test
    void brokenJson() throws Exception {
        expect(400, "MALFORMED_BODY", json(post("/auth/login"), "{\"email\": "))
                .andExpect(jsonPath("$.detail").value("The request body is missing or isn't valid JSON."));
    }

    @Test
    void missingParameter() throws Exception {
        expect(400, "MISSING_PARAMETER", post("/auth/reset-password"));
    }

    @Test
    void missingCookie() throws Exception {
        expect(400, "MISSING_COOKIE", post("/auth/refresh"));
    }

    @Test
    void wrongParameterType() throws Exception {
        expect(400, "INVALID_PARAMETER", as(admin(), get("/api/v1/admin/users/abc")))
                .andExpect(jsonPath("$.detail").value("Parameter 'id' has an invalid value."));
    }

    @Test
    void unknownPath() throws Exception {
        expect(404, "NOT_FOUND", get("/auth/no-such-endpoint"));
    }

    @Test
    void wrongMethodNamesTheAllowedOnes() throws Exception {
        expect(405, "METHOD_NOT_ALLOWED", delete("/auth/login"))
                .andExpect(header().string(HttpHeaders.ALLOW, "POST"));
    }

    @Test
    void wrongContentType() throws Exception {
        expect(415, "UNSUPPORTED_MEDIA_TYPE",
                post("/auth/login").contentType(MediaType.TEXT_PLAIN).content("hello"));
    }

    // ---- login and tokens ----------------------------------------------------------

    @Test
    void noToken() throws Exception {
        expect(401, "AUTHENTICATION_REQUIRED", get("/user/get-info"));
    }

    /** A browser page load asks for HTML; the error must still be readable. */
    @Test
    void noTokenAndAClientThatWantsHtml() throws Exception {
        expect(401, "AUTHENTICATION_REQUIRED", get("/user/get-info").accept(MediaType.TEXT_HTML));
    }

    @Test
    void expiredTokenWithoutTheLibrarysMessage() throws Exception {
        String expired = Jwts.builder().subject("jane@example.com")
                .expiration(Date.from(Instant.now().minusSeconds(60)))
                .signWith(Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret)), Jwts.SIG.HS256).compact();

        expect(401, "TOKEN_EXPIRED", as(expired, get("/user/get-info")))
                .andExpect(jsonPath("$.detail").value("The access token has expired."));
    }

    @Test
    void wrongPassword() throws Exception {
        expect(401, "INVALID_CREDENTIALS",
                json(post("/auth/login"), "{\"email\": \"nobody@example.com\", \"password\": \"x\"}"));
    }

    @Test
    void unverifiedAccount() throws Exception {
        String email = uniqueEmail();
        register(email, PASSWORD);
        login(email, PASSWORD).andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("ACCOUNT_DISABLED"));
    }

    @Test
    void notAnAdmin() throws Exception {
        expect(403, "ACCESS_DENIED", as(registerVerifiedUserAndLogin(uniqueEmail()), get("/api/v1/admin/users")));
    }

    @Test
    void codeAlreadySent() throws Exception {
        String accessToken = registerVerifiedUserAndLogin(uniqueEmail());
        mvc.perform(as(accessToken, delete("/user/delete"))).andExpect(status().isOk());
        expect(409, "TOKEN_ALREADY_EXISTS", as(accessToken, delete("/user/delete")));
    }

    // ---- users ---------------------------------------------------------------------

    @Test
    void takenEmail() throws Exception {
        String email = uniqueEmail();
        register(email, PASSWORD);
        register(email, PASSWORD).andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("USER_ALREADY_EXISTS"));
    }

    @Test
    void unknownUser() throws Exception {
        expect(404, "USER_NOT_FOUND", as(admin(), get("/api/v1/admin/users/999999999")));
    }

    // ---- helpers -------------------------------------------------------------------

    private ResultActions expect(int status, String code, MockHttpServletRequestBuilder request) throws Exception {
        return mvc.perform(request)
                .andExpect(status().is(status))
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.status").value(status))
                .andExpect(jsonPath("$.code").value(code))
                .andExpect(jsonPath("$.msg").isNotEmpty())
                .andExpect(jsonPath("$.detail").isNotEmpty())
                .andExpect(content().string(not(containsString("Exception"))));
    }

    private static MockHttpServletRequestBuilder json(MockHttpServletRequestBuilder request, String body) {
        return request.contentType(MediaType.APPLICATION_JSON).content(body);
    }

    private static MockHttpServletRequestBuilder as(String accessToken, MockHttpServletRequestBuilder request) {
        return request.header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken);
    }

    private String admin() throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);
        adminBootstrap.promote(List.of(email));
        return accessToken;
    }
}
