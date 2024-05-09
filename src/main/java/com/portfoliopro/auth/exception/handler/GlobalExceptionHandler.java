package com.portfoliopro.auth.exception.handler;

import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import com.portfoliopro.auth.exception.handler.impl.HttpExceptionHandler;
import com.portfoliopro.auth.exception.handler.impl.TokenExceptionHandler;
import com.portfoliopro.auth.exception.handler.impl.UserExceptionHandler;

@ControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(Exception.class)
    public ProblemDetail handleException(Exception e) {

        AuthExceptionHandler handler1 = new UserExceptionHandler();
        AuthExceptionHandler handler2 = new HttpExceptionHandler();
        AuthExceptionHandler handler3 = new TokenExceptionHandler();
        handler1.setNextHandler(handler2);
        handler2.setNextHandler(handler3);

        return handler1.handle(e);
    }
}
