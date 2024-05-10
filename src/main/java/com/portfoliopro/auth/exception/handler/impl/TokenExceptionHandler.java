package com.portfoliopro.auth.exception.handler.impl;

import org.springframework.http.HttpStatusCode;
import org.springframework.http.ProblemDetail;
import org.springframework.security.authentication.InsufficientAuthenticationException;

import com.portfoliopro.auth.exception.ExpireRefreshTokenException;
import com.portfoliopro.auth.exception.InvalidRefreshTokenException;
import com.portfoliopro.auth.exception.handler.AuthExceptionHandler;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.security.SignatureException;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TokenExceptionHandler implements AuthExceptionHandler {
    private AuthExceptionHandler nextHandler;

    @Override
    public ProblemDetail handle(Exception e) {
        ProblemDetail error = null;
        // e.printStackTrace();

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
            error.setProperty("msg", "Invalid JWT token signature");
        }

        if (e instanceof ExpiredJwtException) {
            error = ProblemDetail.forStatusAndDetail(
                    HttpStatusCode.valueOf(403),
                    e.getMessage());
            error.setProperty("msg", "JWT token has expired");
        }

        if (e instanceof ExpireRefreshTokenException) {
            error = ProblemDetail.forStatusAndDetail(
                    HttpStatusCode.valueOf(403),
                    e.getMessage());
            error.setProperty("msg", "Refresh token has expired");
        }

        if (e instanceof InvalidRefreshTokenException) {
            error = ProblemDetail.forStatusAndDetail(
                    HttpStatusCode.valueOf(403),
                    e.getMessage());
            error.setProperty("msg", "Invalid refresh token");
        }

        if (nextHandler == null && error == null) {
            error = ProblemDetail.forStatusAndDetail(
                    HttpStatusCode.valueOf(500),
                    e.getMessage());
            error.setProperty("msg", "An unexpected error occurred");
        }
        if (nextHandler != null && error == null)
            return nextHandler.handle(e);

        return error;
    }
}
