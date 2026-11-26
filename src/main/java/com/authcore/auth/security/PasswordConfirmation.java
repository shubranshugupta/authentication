package com.authcore.auth.security;

/** A logged-in user's password, typed again for an action a stolen access token mustn't be enough for. */
public record PasswordConfirmation(Integer userId, String password, String ip) {

    @Override
    public String toString() {
        return "PasswordConfirmation[userId=" + userId + ", ip=" + ip + "]";
    }
}
