package com.portfoliopro.auth.exception;

public class TokenAlreadyExistsException extends RuntimeException {
    public TokenAlreadyExistsException(String message) {
        super(message);
    }

    public TokenAlreadyExistsException(String message, Throwable cause) {
        super(message, cause);
    }
}
