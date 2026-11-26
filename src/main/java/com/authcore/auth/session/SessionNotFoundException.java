package com.authcore.auth.session;

public class SessionNotFoundException extends RuntimeException {
    public SessionNotFoundException(Long sessionId) {
        super("Session " + sessionId + " not found");
    }
}
