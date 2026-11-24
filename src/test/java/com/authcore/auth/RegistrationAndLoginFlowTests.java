package com.authcore.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.cookie;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import javax.crypto.SecretKey;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;

import com.authcore.auth.entities.User;
import com.authcore.auth.support.IntegrationTest;
import com.jayway.jsonpath.JsonPath;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import jakarta.servlet.http.Cookie;

/** Registration, email verification, login, refresh, and access-token checks. */
class RegistrationAndLoginFlowTests extends IntegrationTest {

    @Value("${auth.token.secret-key}")
    private String jwtSecret;

    // ---- registration and verification ---------------------------------------------

    @Test
    void registerCreatesADisabledUserAndEmailsAVerificationLink() throws Exception {
        String email = uniqueEmail();

        register(email, PASSWORD)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.msg").value("Verification email sent"));

        User user = user(email);
        assertThat(user.isEnabled()).isFalse();
        assertThat(user.getPassword()).isNotEqualTo(PASSWORD).startsWith("$2");

        MimeMessage verificationEmail = awaitEmail(email, "Verify Email");
        assertThat(htmlBody(verificationEmail))
                .contains(verificationToken(email))
                .contains("cid:authcoreLogo")
                .contains("AuthCore");

        // The sender comes from auth.mail.from / from-name, not from the SMTP login.
        InternetAddress from = (InternetAddress) verificationEmail.getFrom()[0];
        assertThat(from.getAddress()).isEqualTo("noreply@authcore.test");
        assertThat(from.getPersonal()).isEqualTo("AuthCore");
    }

    @Test
    void registeringTheSameEmailTwiceReturns409() throws Exception {
        String email = uniqueEmail();
        register(email, PASSWORD).andExpect(status().isOk());

        register(email, PASSWORD).andExpect(status().isConflict());
    }

    @Test
    void loginBeforeVerifyingTheEmailReturns403() throws Exception {
        String email = uniqueEmail();
        register(email, PASSWORD).andExpect(status().isOk());

        login(email, PASSWORD).andExpect(status().isForbidden());
    }

    @Test
    void verifyingTheEmailEnablesTheAccountAndUsesUpTheToken() throws Exception {
        String email = uniqueEmail();
        register(email, PASSWORD).andExpect(status().isOk());

        verifyEmail(email, verificationToken(email))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.msg").value("Email verified successfully"));

        assertThat(user(email).isEnabled()).isTrue();
        assertThat(verificationTokenRepository.findByUser(user(email))).isEmpty();

        verifyEmail(email, "any-token")
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.msg").value("Email already verified"));
    }

    @Test
    void verifyingWithAWrongTokenReturns401AndLeavesTheAccountDisabled() throws Exception {
        String email = uniqueEmail();
        register(email, PASSWORD).andExpect(status().isOk());

        verifyEmail(email, "not-the-real-token").andExpect(status().isUnauthorized());

        assertThat(user(email).isEnabled()).isFalse();
    }

    // ---- login ---------------------------------------------------------------------

    @Test
    void loginReturnsAnAccessTokenAndAnHttpOnlyRefreshCookie() throws Exception {
        String email = uniqueEmail();
        registerVerifiedUserAndLogin(email);

        login(email, PASSWORD)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(cookie().exists("refreshToken"))
                .andExpect(cookie().httpOnly("refreshToken", true));
    }

    @Test
    void loginWithAWrongPasswordReturns401() throws Exception {
        String email = uniqueEmail();
        registerVerifiedUserAndLogin(email);

        login(email, "wrong-password").andExpect(status().isUnauthorized());
    }

    /** Current behaviour, recorded on purpose. H2 changes this to 401 so emails can't be probed. */
    @Test
    void loginWithAnUnknownEmailReturns404() throws Exception {
        login(uniqueEmail(), PASSWORD).andExpect(status().isNotFound());
    }

    // ---- refresh -------------------------------------------------------------------

    @Test
    void refreshReturnsAWorkingAccessToken() throws Exception {
        String email = uniqueEmail();
        registerVerifiedUserAndLogin(email);
        Cookie refreshCookie = refreshCookie(email, PASSWORD);

        // Twice: the first call reads the token from MySQL, the second from the Redis cache.
        for (int i = 0; i < 2; i++) {
            String body = mvc.perform(post("/auth/refresh").cookie(refreshCookie))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.accessToken").isNotEmpty())
                    .andReturn().getResponse().getContentAsString();

            getProfile(JsonPath.read(body, "$.accessToken"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.email").value(email));
        }
    }

    @Test
    void refreshWithAnUnknownTokenReturns401() throws Exception {
        mvc.perform(post("/auth/refresh").cookie(new Cookie("refreshToken", "not-a-real-token")))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void refreshWithoutTheCookieReturns400() throws Exception {
        mvc.perform(post("/auth/refresh")).andExpect(status().isBadRequest());
    }

    // ---- access tokens -------------------------------------------------------------

    @Test
    void profileReturnsTheLoggedInUser() throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);

        getProfile(accessToken)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value(email))
                .andExpect(jsonPath("$.firstName").value("jane"))
                .andExpect(jsonPath("$.lastName").value("doe"))
                .andExpect(jsonPath("$.password").doesNotExist());
    }

    @Test
    void protectedEndpointWithoutATokenReturns401() throws Exception {
        mvc.perform(get("/user/get-info")).andExpect(status().isUnauthorized());
    }

    @Test
    void tokenSignedWithAnotherKeyReturns401() throws Exception {
        String email = uniqueEmail();
        registerVerifiedUserAndLogin(email);
        SecretKey otherKey = Keys.hmacShaKeyFor(
                Decoders.BASE64.decode("YW5vdGhlci1rZXktdGhhdC10aGUtc2VydmVyLWRvZXMtbm90LWtub3ctYWJvdXQ="));

        getProfile(token(email, otherKey, Instant.now().plus(1, ChronoUnit.HOURS)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void expiredTokenReturns401() throws Exception {
        String email = uniqueEmail();
        registerVerifiedUserAndLogin(email);
        SecretKey serverKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));

        getProfile(token(email, serverKey, Instant.now().minus(1, ChronoUnit.MINUTES)))
                .andExpect(status().isUnauthorized());
    }

    /** Current behaviour, recorded on purpose. A2/M6 change this to 401. */
    @Test
    void malformedTokenReturns500() throws Exception {
        mvc.perform(get("/user/get-info").header(HttpHeaders.AUTHORIZATION, "Bearer not-a-jwt"))
                .andExpect(status().isInternalServerError());
    }

    private static String token(String email, SecretKey key, Instant expiresAt) {
        return Jwts.builder()
                .subject(email)
                .issuedAt(Date.from(expiresAt.minus(2, ChronoUnit.HOURS)))
                .expiration(Date.from(expiresAt))
                .signWith(key, Jwts.SIG.HS256)
                .compact();
    }
}
