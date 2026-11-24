package com.authcore.auth.exception;

public class UserNotFoundException extends RuntimeException {
    public UserNotFoundException(Integer id) {
        super("User " + id + " not found");
    }
}
