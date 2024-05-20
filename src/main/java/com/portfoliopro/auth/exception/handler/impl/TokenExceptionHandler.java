package com.portfoliopro.auth.exception.handler.impl;

import org.springframework.http.HttpStatusCode;
import org.springframework.http.ProblemDetail;
import org.springframework.security.authentication.InsufficientAuthenticationException;

import com.portfoliopro.auth.exception.InvalidTokenException;
import com.portfoliopro.auth.exception.TokenAlreadyExistsException;
import com.portfoliopro.auth.exception.TokenExpireException;
import com.portfoliopro.auth.exception.handler.AuthExceptionHandler;

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
                    HttpStatusCode.valueOf(403),
                    e.getMessage());
            error.setProperty("msg", "Invalid Token signature");
        }

        if (e instanceof ExpiredJwtException) {
            error = ProblemDetail.forStatusAndDetail(
                    HttpStatusCode.valueOf(403),
                    e.getMessage());
            error.setProperty("msg", "Token has expired");
        }

        if (e instanceof TokenExpireException) {
            error = ProblemDetail.forStatusAndDetail(
                    HttpStatusCode.valueOf(403),
                    e.getMessage());
            error.setProperty("msg", "Token has expired");
        }

        if (e instanceof InvalidTokenException) {
            error = ProblemDetail.forStatusAndDetail(
                    HttpStatusCode.valueOf(403),
                    e.getMessage());
            error.setProperty("msg", "Invalid Token");
        }

        if (e instanceof TokenAlreadyExistsException) {
            error = ProblemDetail.forStatusAndDetail(
                    HttpStatusCode.valueOf(403),
                    e.getMessage());
            error.setProperty("msg", "Token already exists");
        }

        if (nextHandler == null && error == null) {
            error = ProblemDetail.forStatusAndDetail(
                    HttpStatusCode.valueOf(500),
                    e.getMessage());
            error.setProperty("msg", "An unexpected error occurred");
            log.error(e.getMessage(), e);
        }
        if (nextHandler != null && error == null)
            return nextHandler.handle(e);

        return error;
    }
}
