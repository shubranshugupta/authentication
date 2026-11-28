package com.authcore.auth.user.account;

/** The new email is the current one, or the email was changed too recently to change again. */
public class EmailChangeRefusedException extends RuntimeException {
    public EmailChangeRefusedException(String message) {
        super(message);
    }
}
