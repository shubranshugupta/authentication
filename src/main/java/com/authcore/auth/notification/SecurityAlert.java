package com.authcore.auth.notification;

/**
 * Emails that tell the owner something happened to their account (F5). They can't be turned
 * off: they are how an owner finds out that somebody else has their password.
 */
public enum SecurityAlert {
    NEW_DEVICE_LOGIN("New sign-in to your AuthCore account", "New sign-in",
            "Your account was just signed in to from a browser or app that hasn't been used with it before.",
            "If this was you, there's nothing to do. If it wasn't, reset your password now with \"Forgot password\": that logs out every device."),
    PASSWORD_CHANGED("Your AuthCore password was changed", "Your password was changed",
            "The password of your account was changed by someone signed in to it. Every other device was logged out.",
            "If this was you, there's nothing to do. If it wasn't, reset your password now with \"Forgot password\": the code is sent to this email, and resetting logs out every device."),
    PASSWORD_RESET("Your AuthCore password was reset", "Your password was reset",
            "The password of your account was reset with a code sent to this email. Every device was logged out.",
            "If this was you, there's nothing to do. If it wasn't, someone can read your email: secure your email account, then reset your password again."),
    SESSIONS_ENDED("You were logged out of AuthCore everywhere", "You were logged out everywhere",
            "One of your sign-ins was used from two places, so someone may have a copy of it. To be safe, every device was logged out.",
            "Sign in again. If you didn't expect this, change your password."),
    GOOGLE_LINKED("Google sign-in was added to your AuthCore account", "Google sign-in added",
            "Your account was just signed in to with the Google account that has this email address. From now on, \"Sign in with Google\" works for it, as well as your password.",
            "If this was you, there's nothing to do. If it wasn't, someone controls a Google account with your email address: secure it, and reset your AuthCore password with \"Forgot password\"."),
    TWO_FACTOR_ENABLED("Two-factor authentication is on for your AuthCore account", "Two-factor authentication is on",
            "Signing in to your account now needs a code from an authenticator app, as well as the password.",
            "If this was you, keep your recovery codes somewhere safe. If it wasn't, someone has your password: reset it now with \"Forgot password\", and ask an administrator to turn two-factor authentication off."),
    TWO_FACTOR_DISABLED("Two-factor authentication is off for your AuthCore account", "Two-factor authentication is off",
            "Signing in to your account no longer needs a code from an authenticator app, only the password.",
            "If this was you, there's nothing to do. If it wasn't, reset your password now with \"Forgot password\", then turn two-factor authentication on again."),
    TWO_FACTOR_DISABLED_BY_ADMIN("Two-factor authentication is off for your AuthCore account",
            "Two-factor authentication is off",
            "An administrator turned two-factor authentication off for your account, as you asked after losing your phone and recovery codes. Signing in needs only the password now. The address and device below are the administrator's.",
            "Turn two-factor authentication on again with your new phone. If you didn't ask for this, reset your password now with \"Forgot password\"."),
    RECOVERY_CODE_USED("A recovery code was used to sign in to AuthCore", "A recovery code was used",
            "Your account was signed in to with one of its recovery codes instead of a code from the app. Each recovery code works once.",
            "If this was you and you lost your phone, turn two-factor authentication off and on again with your new phone. If it wasn't you, reset your password now with \"Forgot password\", and make new recovery codes.");

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
