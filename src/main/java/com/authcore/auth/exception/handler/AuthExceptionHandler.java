package com.authcore.auth.exception.handler;

import org.springframework.http.ProblemDetail;

public interface AuthExceptionHandler {
    public void setNextHandler(AuthExceptionHandler handler);

    public AuthExceptionHandler getNextHandler();

    public ProblemDetail handle(Exception e);
}
