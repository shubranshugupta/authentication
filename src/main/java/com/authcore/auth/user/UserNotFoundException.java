package com.authcore.auth.user;

public class UserNotFoundException extends RuntimeException {
    public UserNotFoundException(Integer id) {
        super("User " + id + " not found");
    }
}
