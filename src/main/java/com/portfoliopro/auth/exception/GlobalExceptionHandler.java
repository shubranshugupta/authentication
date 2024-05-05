package com.portfoliopro.auth.exception;

import org.springframework.http.HttpStatusCode;
import org.springframework.http.ProblemDetail;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AccountStatusException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.security.SignatureException;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(Exception.class)
    @SuppressWarnings("unused")
    public ProblemDetail handleException(Exception e) {
        ProblemDetail error = null;
        e.printStackTrace();

        if (e instanceof UsernameNotFoundException) {
            error = ProblemDetail.forStatusAndDetail(
                    HttpStatusCode.valueOf(404),
                    e.getMessage());
            error.setProperty("description", "User not found");

        }

        if (e instanceof BadCredentialsException) {
            error = ProblemDetail.forStatusAndDetail(
                    HttpStatusCode.valueOf(401),
                    e.getMessage());
            error.setProperty("description", "Invalid username or password.");
        }

        if (e instanceof AccountStatusException) {
            error = ProblemDetail.forStatusAndDetail(
                    HttpStatusCode.valueOf(403),
                    e.getMessage());
            error.setProperty("description", "Account is disabled.");
        }

        if (e instanceof AccessDeniedException) {
            error = ProblemDetail.forStatusAndDetail(
                    HttpStatusCode.valueOf(403),
                    e.getMessage());
            error.setProperty("description", "You are not authorized to access this resource");
        }

        if (e instanceof SignatureException) {
            error = ProblemDetail.forStatusAndDetail(
                    HttpStatusCode.valueOf(403),
                    e.getMessage());
            error.setProperty("description", "Invalid JWT token signature");
        }

        if (e instanceof ExpiredJwtException) {
            error = ProblemDetail.forStatusAndDetail(
                    HttpStatusCode.valueOf(403),
                    e.getMessage());
            error.setProperty("description", "JWT token has expired");
        }

        if (e == null) {
            error = ProblemDetail.forStatusAndDetail(
                    HttpStatusCode.valueOf(500),
                    e.getMessage());
            error.setProperty("description", "An unexpected error occurred");
        }

        return error;
    }
}
