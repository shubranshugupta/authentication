package com.authcore.auth.common;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Base64;
import java.util.Set;
import java.util.stream.Collectors;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;

import com.authcore.auth.common.AuthConfigProperties.CookieConfigProperties;
import com.authcore.auth.common.AuthConfigProperties.TokenConfigProperties;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;

/** Startup checks on auth.* settings (they run when Spring binds AuthConfigProperties). */
class AuthConfigPropertiesTests {
    private static final ValidatorFactory FACTORY = Validation.buildDefaultValidatorFactory();
    private static final Validator VALIDATOR = FACTORY.getValidator();

    @AfterAll
    static void close() {
        FACTORY.close();
    }

    @Test
    void cookieDefaultsAreSecureAndStrict() {
        CookieConfigProperties cookie = new CookieConfigProperties();

        assertThat(cookie.isSecure()).isTrue();
        assertThat(cookie.getSameSite()).isEqualTo("Strict");
        assertThat(VALIDATOR.validate(cookie)).isEmpty();
    }

    @Test
    void sameSiteNoneIsAllowedOnlyWithSecure() {
        CookieConfigProperties cookie = new CookieConfigProperties();
        cookie.setSameSite("None");
        assertThat(VALIDATOR.validate(cookie)).isEmpty();

        cookie.setSecure(false);
        assertThat(messages(VALIDATOR.validate(cookie)))
                .containsExactly("auth.cookie.same-site=None requires auth.cookie.secure=true (browsers reject it otherwise)");
    }

    @Test
    void unknownSameSiteValueIsRejected() {
        CookieConfigProperties cookie = new CookieConfigProperties();
        cookie.setSameSite("strict-ish");

        assertThat(messages(VALIDATOR.validate(cookie)))
                .containsExactly("auth.cookie.same-site must be Strict, Lax or None");
    }

    @Test
    void secretKeyMustBeAtLeast32BytesOfBase64() {
        String problem = "auth.token.secret-key (JWT_SECRET_KEY) must be a base64 key of at least 32 bytes";

        assertThat(VALIDATOR.validate(token(base64(32)))).isEmpty();
        assertThat(messages(VALIDATOR.validate(token(base64(31))))).containsExactly(problem);
        assertThat(messages(VALIDATOR.validate(token("")))).containsExactly(problem);
        assertThat(messages(VALIDATOR.validate(token(null)))).containsExactly(problem);
        // What an unset variable is bound as.
        assertThat(messages(VALIDATOR.validate(token("${JWT_SECRET_KEY}")))).containsExactly(problem);
    }

    /** Spring prints the rejected value when startup fails. */
    @Test
    void aRejectedSecretKeyIsNeverPrinted() {
        TokenConfigProperties weak = token("c2VjcmV0");

        assertThat(VALIDATOR.validate(weak)).extracting(violation -> String.valueOf(violation.getInvalidValue()))
                .containsExactly("false");
        assertThat(weak.toString()).doesNotContain("c2VjcmV0");
    }

    @Test
    void expirationsMustBePositive() {
        TokenConfigProperties token = token(base64(32));
        token.setJwtExpiration(0);
        token.setRefreshExpiration(-1);

        assertThat(VALIDATOR.validate(token)).hasSize(2);
    }

    private static TokenConfigProperties token(String secretKey) {
        TokenConfigProperties token = new TokenConfigProperties();
        token.setSecretKey(secretKey);
        token.setJwtExpiration(1);
        token.setRefreshExpiration(1);
        return token;
    }

    private static String base64(int bytes) {
        return Base64.getEncoder().encodeToString(new byte[bytes]);
    }

    private static Set<String> messages(Set<? extends ConstraintViolation<?>> violations) {
        return violations.stream().map(ConstraintViolation::getMessage).collect(Collectors.toSet());
    }
}
