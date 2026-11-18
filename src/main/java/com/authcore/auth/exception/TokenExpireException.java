package com.authcore.auth.exception;

public class TokenExpireException extends RuntimeException {
    public TokenExpireException(String message) {
        super(message);
    }

    public TokenExpireException(String message, Throwable cause) {
        super(message, cause);
    }
}
