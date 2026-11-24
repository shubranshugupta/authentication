package com.authcore.auth.common;

import java.nio.charset.StandardCharsets;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class PasswordValidator implements ConstraintValidator<ValidPassword, String> {
    public static final int MIN_CHARACTERS = 12;
    public static final int MAX_BYTES = 72;

    @Override
    public boolean isValid(String password, ConstraintValidatorContext context) {
        if (password == null)
            return true;

        // Count characters as people see them, so "é" or an emoji counts once.
        int characters = password.codePointCount(0, password.length());
        if (characters < MIN_CHARACTERS)
            return fail(context, "must be at least " + MIN_CHARACTERS + " characters");

        if (password.getBytes(StandardCharsets.UTF_8).length > MAX_BYTES)
            return fail(context, "must be at most " + MAX_BYTES + " bytes (about " + MAX_BYTES
                    + " letters or digits; accented letters and emoji take 2-4 bytes each)");

        return true;
    }

    private static boolean fail(ConstraintValidatorContext context, String message) {
        context.disableDefaultConstraintViolation();
        context.buildConstraintViolationWithTemplate(message).addConstraintViolation();
        return false;
    }
}
