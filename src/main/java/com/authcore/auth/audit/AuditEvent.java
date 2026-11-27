package com.authcore.auth.audit;

/** What the audit log records (F2). The names are part of the log format: don't rename them. */
public enum AuditEvent {
    /**
     * With "sessionId", "newDevice" (true if the owner was emailed about it), for a user with
     * two-factor authentication "secondFactor" (APP or RECOVERY_CODE), and "via" GOOGLE for a
     * sign-in with Google.
     */
    LOGIN_SUCCEEDED,
    /**
     * With "reason": WRONG_PASSWORD, UNKNOWN_ACCOUNT, EMAIL_NOT_VERIFIED, ACCOUNT_LOCKED,
     * RATE_LIMITED, ACCOUNT_CHANGED, at the second step WRONG_CODE, CODE_RATE_LIMITED or
     * EXPIRED, or with "via" GOOGLE one of SocialLoginException's reasons.
     */
    LOGIN_FAILED,
    /** The password (or Google) was right; the login waits for the code from the app ("via"). */
    SECOND_FACTOR_REQUIRED,
    /** A new account made by signing in with Google. */
    GOOGLE_SIGN_UP,
    /**
     * Google was linked to the account with its email; "unverifiedAccount" if that account
     * was never verified and was taken over.
     */
    GOOGLE_LINKED,
    TWO_FACTOR_ENABLED,
    /** By the user, or by the admin "by". */
    TWO_FACTOR_DISABLED,
    RECOVERY_CODES_RENEWED,
    /** The user logged out of this session ("sessionId"). */
    LOGOUT,
    /** The user logged one of their devices out ("sessionId"). */
    SESSION_ENDED,
    /** The user logged out of all devices. */
    ALL_SESSIONS_ENDED,
    /** A used refresh token came back: somebody has a copy. All of the user's sessions ended. */
    REFRESH_TOKEN_REUSED,
    /** With an emailed code. All of the user's sessions ended. */
    PASSWORD_RESET,
    /** By the logged-in user, who stays logged in on this session ("sessionId"). All other sessions ended. */
    PASSWORD_CHANGED,
    /** The user confirmed a new email with the code sent to it. Neither address is logged. */
    EMAIL_CHANGED,
    /** The link sent to the old address changed the email back and set a new password. All sessions ended. */
    EMAIL_CHANGE_UNDONE,
    ACCOUNT_DELETED,
    /**
     * A password typed again, for an admin action or a password change, was wrong
     * ("reason": WRONG_PASSWORD or RATE_LIMITED).
     */
    PASSWORD_CONFIRMATION_FAILED,
    /** By the admin "by". */
    USER_LOCKED,
    /** By the admin "by". */
    USER_UNLOCKED,
    /** The admin "by" logged the user out of all devices. */
    USER_LOGGED_OUT,
    /** The admin "by" gave the user the "role". */
    ROLE_CHANGED
}
