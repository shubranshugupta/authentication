package com.authcore.auth.notification;

/**
 * Emails that tell the owner something happened to their account (F5). They can't be turned
 * off: they are how an owner finds out that somebody else has their password.
 */
public enum SecurityAlert {
    PASSWORD_CHANGED("Your AuthCore password was changed", "Your password was changed",
            "The password of your account was changed by someone signed in to it. Every other device was logged out.",
            "If this was you, there's nothing to do. If it wasn't, reset your password now with \"Forgot password\": the code is sent to this email, and resetting logs out every device."),
    PASSWORD_RESET("Your AuthCore password was reset", "Your password was reset",
            "The password of your account was reset with a code sent to this email. Every device was logged out.",
            "If this was you, there's nothing to do. If it wasn't, someone can read your email: secure your email account, then reset your password again."),
    SESSIONS_ENDED("You were logged out of AuthCore everywhere", "You were logged out everywhere",
            "One of your sign-ins was used from two places, so someone may have a copy of it. To be safe, every device was logged out.",
            "Sign in again. If you didn't expect this, change your password.");

    final String subject;
    final String heading;
    final String message;
    final String advice;

    SecurityAlert(String subject, String heading, String message, String advice) {
        this.subject = subject;
        this.heading = heading;
        this.message = message;
        this.advice = advice;
    }

    public String subject() {
        return subject;
    }
}
