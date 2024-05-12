package com.portfoliopro.auth.exception;

public class ExpireOtpException extends RuntimeException {
    public ExpireOtpException(String message) {
        super(message);
    }

    public ExpireOtpException(String message, Throwable cause) {
        super(message, cause);
    }
}
