package com.authcore.auth.token;

import java.time.Duration;

import org.jspecify.annotations.Nullable;

/**
 * Everything a one-time token can be for. A new purpose needs a constant here and an
 * email template, nothing else.
 */
public enum TokenPurpose {
    EMAIL_VERIFICATION(Duration.ofHours(24), "/auth/verify-email", "Verify Email", "verify_registration_email"),
    PASSWORD_RESET(Duration.ofMinutes(15), null, "Password Reset", "password_reset_email"),
    ACCOUNT_DELETION(Duration.ofMinutes(10), null, "Delete Account", "delete_account_email");

    final Duration validFor;
    /** The page the emailed link opens. Without one, the email shows a code to type in. */
    final @Nullable String page;
    final String emailSubject;
    final String emailTemplate;

    TokenPurpose(Duration validFor, @Nullable String page, String emailSubject, String emailTemplate) {
        this.validFor = validFor;
        this.page = page;
        this.emailSubject = emailSubject;
        this.emailTemplate = emailTemplate;
    }

    boolean isLink() {
        return page != null;
    }

    /** For the email, e.g. "24 hours" or "15 minutes". */
    String validForText() {
        return validFor.toHours() > 0 ? validFor.toHours() + " hours" : validFor.toMinutes() + " minutes";
    }
}
