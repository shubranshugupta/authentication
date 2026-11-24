package com.authcore.auth.common;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;

/** The password policy: at least 12 characters, at most 72 bytes (bcrypt's limit). */
class PasswordValidatorTests {
    private static final ValidatorFactory FACTORY = Validation.buildDefaultValidatorFactory();
    private static final Validator VALIDATOR = FACTORY.getValidator();

    record Form(@ValidPassword String password) {
    }

    @AfterAll
    static void close() {
        FACTORY.close();
    }

    @Test
    void twelveCharactersIsTheMinimum() {
        assertThat(errors("a".repeat(11))).containsExactly("must be at least 12 characters");
        assertThat(errors("a".repeat(12))).isEmpty();
    }

    @Test
    void seventyTwoBytesIsTheMaximum() {
        assertThat(errors("a".repeat(72))).isEmpty();
        assertThat(errors("a".repeat(73))).singleElement().asString().startsWith("must be at most 72 bytes");
    }

    @Test
    void multiByteCharactersCountOnceForLengthButFullyForBytes() {
        // "é" is 1 character but 2 bytes in UTF-8.
        assertThat(errors("é".repeat(12))).isEmpty();               // 12 characters, 24 bytes
        assertThat(errors("é".repeat(37))).hasSize(1);               // 37 characters, 74 bytes
        // An emoji is 1 character (2 Java chars, 4 bytes).
        assertThat(errors("🔒".repeat(11) + "a")).isEmpty();         // 12 characters, 45 bytes
        assertThat(errors("🔒".repeat(6))).containsExactly("must be at least 12 characters");
    }

    @Test
    void nullIsLeftToNotBlank() {
        assertThat(errors(null)).isEmpty();
    }

    private static List<String> errors(String password) {
        return VALIDATOR.validate(new Form(password)).stream().map(ConstraintViolation::getMessage).toList();
    }
}
