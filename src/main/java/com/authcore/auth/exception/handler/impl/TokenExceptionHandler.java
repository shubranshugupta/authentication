package com.authcore.auth.exception.handler.impl;

import org.springframework.http.HttpStatusCode;
import org.springframework.http.ProblemDetail;
import org.springframework.security.authentication.InsufficientAuthenticationException;

import com.authcore.auth.exception.InvalidTokenException;
import com.authcore.auth.exception.TokenAlreadyExistsException;
import com.authcore.auth.exception.TokenExpireException;
import com.authcore.auth.exception.handler.AuthExceptionHandler;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.security.SignatureException;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Data
@Slf4j
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TokenExceptionHandler implements AuthExceptionHandler {
    private AuthExceptionHandler nextHandler;

    @Override
    public ProblemDetail handle(Exception e) {
        ProblemDetail error = null;

        if (e instanceof InsufficientAuthenticationException) {
            error = ProblemDetail.forStatusAndDetail(
                    HttpStatusCode.valueOf(401),
                    e.getMessage());
            error.setProperty("msg", "JWT token is missing");
        }

        if (e instanceof SignatureException) {
            error = ProblemDetail.forStatusAndDetail(
                    HttpStatusCode.valueOf(401),
                    e.getMessage());
            error.setProperty("msg", "Invalid Token signature");
        }

        if (e instanceof ExpiredJwtException) {
            error = ProblemDetail.forStatusAndDetail(
                    HttpStatusCode.valueOf(401),
                    e.getMessage());
            error.setProperty("msg", "Token has expired");
        }

        if (e instanceof TokenExpireException) {
            error = ProblemDetail.forStatusAndDetail(
                    HttpStatusCode.valueOf(401),
                    e.getMessage());
            error.setProperty("msg", "Token has expired");
        }

        if (e instanceof InvalidTokenException) {
            error = ProblemDetail.forStatusAndDetail(
                    HttpStatusCode.valueOf(401),
                    e.getMessage());
            error.setProperty("msg", "Invalid Token");
        }

        if (e instanceof TokenAlreadyExistsException) {
            error = ProblemDetail.forStatusAndDetail(
                    HttpStatusCode.valueOf(409),
                    e.getMessage());
            error.setProperty("msg", "Token already exists");
        }

        if (nextHandler == null && error == null) {
            error = ProblemDetail.forStatusAndDetail(
                    HttpStatusCode.valueOf(500),
                    "An unexpected error occurred.");
            // The details stay in the server log only (H2).
            error.setProperty("msg", "An unexpected error occurred");
            log.error(e.getMessage(), e);
        }
        if (nextHandler != null && error == null)
            return nextHandler.handle(e);

        return error;
    }
}
