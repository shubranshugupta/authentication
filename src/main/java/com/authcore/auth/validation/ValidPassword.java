package com.authcore.auth.validation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

/**
 * The password policy for new passwords (registration and reset): at least
 * {@value PasswordValidator#MIN_CHARACTERS} characters and at most
 * {@value PasswordValidator#MAX_BYTES} bytes in UTF-8. bcrypt ignores everything
 * after 72 bytes, so a longer password would only look stronger than it is.
 * null is left to @NotBlank.
 */
@Documented
@Constraint(validatedBy = PasswordValidator.class)
@Target({ ElementType.FIELD, ElementType.PARAMETER })
@Retention(RetentionPolicy.RUNTIME)
public @interface ValidPassword {
    String message() default "must be at least 12 characters and at most 72 bytes";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}
