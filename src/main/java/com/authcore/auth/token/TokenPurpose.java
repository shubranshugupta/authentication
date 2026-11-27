package com.authcore.auth.token;

import java.time.Duration;

import org.jspecify.annotations.Nullable;

/**
 * Everything a one-time token can be for. A new purpose needs a constant here and an
 * email template, nothing else.
 */
public enum TokenPurpose {
    EMAIL_VERIFICATION(Duration.ofHours(24), "/verify-email", "Verify Email", "verify_registration_email"),
    PASSWORD_RESET(Duration.ofMinutes(15), null, "Password Reset", "password_reset_email"),
    ACCOUNT_DELETION(Duration.ofMinutes(10), null, "Delete Account", "delete_account_email"),
    /** Sent to the new address, which it confirms. */
    EMAIL_CHANGE(Duration.ofMinutes(15), null, "Confirm your new AuthCore email", "change_email_email"),
    /** Sent to the old address, which it changes the account back to. */
    EMAIL_CHANGE_UNDO(Duration.ofDays(7), "/undo-email-change", "Your AuthCore email was changed",
            "email_changed_email");

    final Duration validFor;
    /** The page of the web app the emailed link opens. Without one, the email shows a code to type in. */
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

    /** For the email, e.g. "7 days", "24 hours" or "15 minutes". */
    String validForText() {
        if (validFor.toDays() > 1)
            return validFor.toDays() + " days";
        return validFor.toHours() > 0 ? validFor.toHours() + " hours" : validFor.toMinutes() + " minutes";
    }
}
