package com.portfoliopro.auth.exception;

public class ExpireVerificationTokenException extends RuntimeException {
    public ExpireVerificationTokenException(String message) {
        super(message);
    }

    public ExpireVerificationTokenException(String message, Throwable cause) {
        super(message, cause);
    }
}
