package com.authcore.auth.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Set;
import java.util.stream.Collectors;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;

import com.authcore.auth.config.properties.AuthConfigProperties.CookieConfigProperties;

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

    private static Set<String> messages(Set<? extends ConstraintViolation<?>> violations) {
        return violations.stream().map(ConstraintViolation::getMessage).collect(Collectors.toSet());
    }
}
