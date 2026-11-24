package com.authcore.auth.token;

/** A code or link from an email is wrong, expired, already used, or was guessed at too often. */
public class InvalidCodeException extends RuntimeException {
    public InvalidCodeException(String message) {
        super(message);
    }
}
