package com.authcore.auth.user;

public class AdminActionRefusedException extends RuntimeException {
    public AdminActionRefusedException(String message) {
        super(message);
    }
}
