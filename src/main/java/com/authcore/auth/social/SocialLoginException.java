package com.authcore.auth.social;

import lombok.Getter;

/**
 * Why a Google sign-in can't go on. The reason goes to the web app in the redirect
 * ({@code #error=...}), so it says nothing a stranger mustn't know.
 */
@Getter
public class SocialLoginException extends RuntimeException {
    /** Google doesn't say the email is verified (or gives none). */
    static final String EMAIL_NOT_VERIFIED = "EMAIL_NOT_VERIFIED";
    /** The account with this email is linked to another Google account. */
    static final String OTHER_GOOGLE_ACCOUNT = "OTHER_GOOGLE_ACCOUNT";
    /** An email change can still be undone to this address. */
    static final String EMAIL_UNAVAILABLE = "EMAIL_UNAVAILABLE";
    /** An administrator locked the account. */
    static final String ACCOUNT_LOCKED = "ACCOUNT_LOCKED";
    /** Google said no, the user cancelled, or the request was made up or too old. */
    static final String FAILED = "GOOGLE_SIGN_IN_FAILED";

    private final String reason;

    SocialLoginException(String reason) {
        super(reason);
        this.reason = reason;
    }
}
