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

import com.authcore.auth.support.IntegrationTest;
import com.authcore.auth.user.User;
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
                .contains("https://app.authcore.test/verify-email?token=" + verificationToken(email) + "\"")
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

        verifyEmail(verificationToken(email))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.msg").value("Email verified successfully"));

        assertThat(user(email).isEnabled()).isTrue();

        // Using the link again: the same answer as for any invalid link. It used to be
        // "Email already verified", which told anyone whether an email was verified (H2).
        verifyEmail(verificationToken(email)).andExpect(status().isBadRequest());
    }

    @Test
    void verifyingWithAWrongTokenReturns400AndLeavesTheAccountDisabled() throws Exception {
        String email = uniqueEmail();
        register(email, PASSWORD).andExpect(status().isOk());

        verifyEmail("not-the-real-token")
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_CODE"));

        assertThat(user(email).isEnabled()).isFalse();
    }

    /** H4: the link failed for these addresses, because the email was part of it. */
    @Test
    void theLinkWorksForAnAddressWithSpecialCharacters() throws Exception {
        String email = "jane+tag&x=%41'" + uniqueEmail();
        register(email, PASSWORD).andExpect(status().isOk());

        assertThat(htmlBody(awaitEmail(email, "Verify Email"))).doesNotContain("email=");
        verifyEmail(verificationToken(email)).andExpect(status().isOk());

        login(email, PASSWORD).andExpect(status().isOk());
    }

    /** H4 and A6: opening a URL must not change anything. */
    @Test
    void theOldEndpointsAreGone() throws Exception {
        String email = uniqueEmail();
        register(email, PASSWORD).andExpect(status().isOk());
        String token = verificationToken(email);

        mvc.perform(get("/auth/verify-email").param("email", email).param("token", token)).andExpect(status().isUnauthorized());
        mvc.perform(get("/api/v1/auth/email-verification/confirm").param("token", token)).andExpect(status().isMethodNotAllowed());
        mvc.perform(post("/auth/login")).andExpect(status().isUnauthorized());
        assertThat(user(email).isEnabled()).isFalse();

        String accessToken = registerVerifiedUserAndLogin(uniqueEmail());
        for (String path : new String[] { "/user/get-info", "/user/delete", "/user/hello" })
            mvc.perform(as(accessToken, get(path))).andExpect(status().isNotFound());
    }

    // ---- login ---------------------------------------------------------------------

    @Test
    void loginReturnsAnAccessTokenAndARefreshCookieBrowsersSendBack() throws Exception {
        String email = uniqueEmail();
        registerVerifiedUserAndLogin(email);

        String setCookie = login(email, PASSWORD)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(cookie().exists("refreshToken"))
                .andExpect(cookie().httpOnly("refreshToken", true))
                .andExpect(cookie().secure("refreshToken", true))
                .andExpect(cookie().sameSite("refreshToken", "Strict"))
                .andExpect(cookie().maxAge("refreshToken", 604800))
                .andReturn().getResponse().getHeader(HttpHeaders.SET_COOKIE);

        // A path, not a URL (C5): with "Path=http://localhost:8080/auth" browsers never
        // sent the cookie back. It must be the path of the refresh endpoint (A6).
        assertThat(setCookie).contains("Path=/api/v1/auth;").doesNotContain("http");
    }

    @Test
    void loginWithAWrongPasswordReturns401() throws Exception {
        String email = uniqueEmail();
        registerVerifiedUserAndLogin(email);

        login(email, "wrong-password").andExpect(status().isUnauthorized());
    }

    /** H2: used to return 404, which told anyone the email wasn't registered. */
    @Test
    void loginWithAnUnknownEmailReturns401() throws Exception {
        login(uniqueEmail(), PASSWORD).andExpect(status().isUnauthorized());
    }

    // ---- refresh -------------------------------------------------------------------

    @Test
    void refreshReturnsAWorkingAccessToken() throws Exception {
        String email = uniqueEmail();
        registerVerifiedUserAndLogin(email);
        Cookie refreshCookie = refreshCookie(email, PASSWORD);

        // Twice: the first call reads the token from MySQL, the second from the Redis cache.
        for (int i = 0; i < 2; i++) {
            String body = refresh(refreshCookie)
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
        refresh(new Cookie("refreshToken", "not-a-real-token"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void refreshWithoutTheCookieReturns400() throws Exception {
        mvc.perform(post("/api/v1/auth/refresh")).andExpect(status().isBadRequest());
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
        mvc.perform(get("/api/v1/users/me")).andExpect(status().isUnauthorized());
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

    /** M6: these used to be 500. */
    @Test
    void tokensThatAreNotJwtsReturn401() throws Exception {
        for (String notAJwt : new String[] { "not-a-jwt", "", "a.b.c", "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhIn0.", "%%%" }) {
            getProfile(notAJwt)
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.code").value("INVALID_TOKEN"))
                    .andExpect(jsonPath("$.detail").value("The access token is invalid."));
        }
    }

    /** The server always sets an expiry; a token without one must not live forever. */
    @Test
    void tokenWithoutAnExpiryReturns401() throws Exception {
        String email = uniqueEmail();
        registerVerifiedUserAndLogin(email);
        SecretKey serverKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));

        getProfile(Jwts.builder().subject(email).signWith(serverKey, Jwts.SIG.HS256).compact())
                .andExpect(status().isUnauthorized());
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
