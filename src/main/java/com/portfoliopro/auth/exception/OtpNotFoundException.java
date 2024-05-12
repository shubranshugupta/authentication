package com.portfoliopro.auth.exception;

public class OtpNotFoundException extends RuntimeException {
    public OtpNotFoundException(String message) {
        super(message);
    }

    public OtpNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}
