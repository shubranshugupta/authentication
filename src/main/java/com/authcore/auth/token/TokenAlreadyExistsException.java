package com.authcore.auth.token;

public class TokenAlreadyExistsException extends RuntimeException {
    public TokenAlreadyExistsException(String message) {
        super(message);
    }

    public TokenAlreadyExistsException(String message, Throwable cause) {
        super(message, cause);
    }
}
