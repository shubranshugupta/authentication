package com.authcore.auth.user.admin;

public class AdminActionRefusedException extends RuntimeException {
    public AdminActionRefusedException(String message) {
        super(message);
    }
}
