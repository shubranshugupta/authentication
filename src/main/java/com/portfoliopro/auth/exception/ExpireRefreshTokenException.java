package com.portfoliopro.auth.exception;

public class ExpireRefreshTokenException extends RuntimeException {
    public ExpireRefreshTokenException(String message) {
        super(message);
    }

    public ExpireRefreshTokenException(String message, Throwable cause) {
        super(message, cause);
    }
}
