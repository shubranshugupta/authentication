package com.authcore.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;

import javax.crypto.SecretKey;

import org.junit.jupiter.api.Test;

import com.authcore.auth.support.IntegrationTest;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

/** H6: what access tokens contain, and which ones are refused. */
class AccessTokenTests extends IntegrationTest {
    private static final String NEW_PASSWORD = "N3w-Str0ng-Passw0rd!";

    // ---- contents ------------------------------------------------------------------

    @Test
    void tokensNameTheUserByIdAndLastFifteenMinutes() throws Exception {
        String email = uniqueEmail();
        Claims claims = claims(registerVerifiedUserAndLogin(email));

        assertThat(claims.getSubject()).isEqualTo(user(email).getId().toString());
        assertThat(claims.getIssuer()).isEqualTo("authcore");
        assertThat(claims.getAudience()).containsExactly("authcore");
        assertThat(claims.get("ver", Integer.class)).isZero();
        assertThat(claims.get("sid", Long.class)).isPositive();
        assertThat(claims.getId()).isNotEmpty();
        assertThat(Duration.between(claims.getIssuedAt().toInstant(), claims.getExpiration().toInstant()))
                .isEqualTo(Duration.ofMinutes(15));
    }

    @Test
    void everyTokenHasItsOwnId() throws Exception {
        String email = uniqueEmail();
        registerVerifiedUserAndLogin(email);

        assertThat(claims(accessToken(email, PASSWORD)).getId())
                .isNotEqualTo(claims(accessToken(email, PASSWORD)).getId());
    }

    // ---- refused tokens ------------------------------------------------------------

    /** Every refusal below changes one thing about this token, which is accepted. */
    @Test
    void aTokenWithEverythingInPlaceIsAccepted() throws Exception {
        getProfile(valid(registerVerifiedUserAndLogin(uniqueEmail())).compact()).andExpect(status().isOk());
    }

    @Test
    void tokenSignedWithAnotherKey() throws Exception {
        SecretKey otherKey = Keys.hmacShaKeyFor(
                Decoders.BASE64.decode("YW5vdGhlci1rZXktdGhhdC10aGUtc2VydmVyLWRvZXMtbm90LWtub3ctYWJvdXQ="));

        assertInvalid(valid(registerVerifiedUserAndLogin(uniqueEmail())).signWith(otherKey, Jwts.SIG.HS256));
    }

    @Test
    void expiredToken() throws Exception {
        String expired = valid(registerVerifiedUserAndLogin(uniqueEmail()))
                .expiration(Date.from(Instant.now().minusSeconds(60))).compact();

        getProfile(expired).andExpect(status().isUnauthorized()).andExpect(jsonPath("$.code").value("TOKEN_EXPIRED"));
    }

    /** M6: these used to be 500. */
    @Test
    void tokensThatAreNotJwts() throws Exception {
        for (String notAJwt : new String[] { "not-a-jwt", "", "a.b.c", "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhIn0.", "%%%" }) {
            getProfile(notAJwt)
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.code").value("INVALID_TOKEN"))
                    .andExpect(jsonPath("$.detail").value("The access token is invalid."));
        }
    }

    /** The server always sets an expiry; a token without one must not live forever. */
    @Test
    void tokenWithoutAnExpiry() throws Exception {
        assertInvalid(valid(registerVerifiedUserAndLogin(uniqueEmail())).expiration(null));
    }

    @Test
    void tokenOfAnotherIssuerOrAudience() throws Exception {
        String accessToken = registerVerifiedUserAndLogin(uniqueEmail());

        assertInvalid(valid(accessToken).issuer("someone-else"));
        assertInvalid(valid(accessToken).issuer(null));
        assertInvalid(valid(accessToken).audience().clear().add("another-service").and());
        assertInvalid(valid(accessToken).audience().clear().and());
    }

    @Test
    void tokenWithAMissingOrBrokenClaim() throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);

        assertInvalid(valid(accessToken).claim("ver", null));
        assertInvalid(valid(accessToken).claim("ver", "zero"));
        assertInvalid(valid(accessToken).claim("sid", null));
        assertInvalid(valid(accessToken).claim("sid", "one"));
        assertInvalid(valid(accessToken).claim("sid", 999999999));
        assertInvalid(valid(accessToken).subject(null));
        assertInvalid(valid(accessToken).subject("999999999"));
        // What tokens contained before H6.
        assertInvalid(valid(accessToken).subject(email));
    }

    @Test
    void tokenWithAnotherUsersSession() throws Exception {
        Object otherSession = claims(registerVerifiedUserAndLogin(uniqueEmail())).get("sid");

        assertInvalid(valid(registerVerifiedUserAndLogin(uniqueEmail())).claim("sid", otherSession));
    }

    /** Sessions end too, but the version alone is enough. */
    @Test
    void tokenWithAnOldVersion() throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);
        jdbc.update("update users set token_version = 1 where id = ?", user(email).getId());

        assertInvalid(valid(accessToken));
        getProfile(valid(accessToken).claim("ver", 1).compact()).andExpect(status().isOk());
    }

    // ---- revoked tokens ------------------------------------------------------------

    /** They used to work for another three hours. */
    @Test
    void aPasswordResetEndsEveryAccessToken() throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);
        requestPasswordReset(email).andExpect(status().isOk());
        getProfile(accessToken).andExpect(status().isOk());

        confirmPasswordReset(email, passwordResetOtp(email), NEW_PASSWORD).andExpect(status().isOk());

        getProfile(accessToken).andExpect(status().isUnauthorized()).andExpect(jsonPath("$.code").value("INVALID_TOKEN"));
        getProfile(accessToken(email, NEW_PASSWORD)).andExpect(status().isOk());
    }

    @Test
    void aWrongResetCodeEndsNothing() throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);
        requestPasswordReset(email).andExpect(status().isOk());

        confirmPasswordReset(email, wrongOtp(passwordResetOtp(email)), NEW_PASSWORD).andExpect(status().isBadRequest());

        getProfile(accessToken).andExpect(status().isOk());
    }

    @Test
    void oneUsersResetDoesntTouchOthers() throws Exception {
        String other = registerVerifiedUserAndLogin(uniqueEmail());
        String email = uniqueEmail();
        registerVerifiedUserAndLogin(email);
        requestPasswordReset(email).andExpect(status().isOk());

        confirmPasswordReset(email, passwordResetOtp(email), NEW_PASSWORD).andExpect(status().isOk());

        getProfile(other).andExpect(status().isOk());
    }

    /** The token named the email, so it worked for whoever registered it next. */
    @Test
    void aDeletedAccountsTokenDoesntWorkForTheNextAccountWithItsEmail() throws Exception {
        String email = uniqueEmail();
        String oldToken = registerVerifiedUserAndLogin(email);
        userRepository.deleteById(user(email).getId());

        register(email, PASSWORD).andExpect(status().isOk());
        awaitEmails(email, "Verify Email", 2);
        verifyEmail(verificationToken(email)).andExpect(status().isOk());
        String newToken = accessToken(email, PASSWORD);

        getProfile(oldToken).andExpect(status().isUnauthorized());
        getProfile(newToken).andExpect(status().isOk());
    }

    // ---- helpers -------------------------------------------------------------------

    /** A copy of this token, to be changed before it's signed. */
    private JwtBuilder valid(String accessToken) {
        return Jwts.builder().claims(claims(accessToken)).signWith(serverKey(), Jwts.SIG.HS256);
    }

    private void assertInvalid(JwtBuilder token) throws Exception {
        getProfile(token.compact())
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("INVALID_TOKEN"))
                .andExpect(jsonPath("$.detail").value("The access token is invalid."));
    }
}
