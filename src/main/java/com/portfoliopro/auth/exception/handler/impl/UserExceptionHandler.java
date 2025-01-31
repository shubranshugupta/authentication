package com.portfoliopro.auth.exception.handler.impl;

import org.springframework.http.HttpStatusCode;
import org.springframework.http.ProblemDetail;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.transaction.TransactionSystemException;

import com.portfoliopro.auth.exception.UserAlreadyExistsException;
import com.portfoliopro.auth.exception.handler.AuthExceptionHandler;

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
public class UserExceptionHandler implements AuthExceptionHandler {
    private AuthExceptionHandler nextHandler;

    @Override
    public ProblemDetail handle(Exception e) {
        ProblemDetail error = null;

        if (e instanceof UserAlreadyExistsException) {
            error = ProblemDetail.forStatusAndDetail(
                    HttpStatusCode.valueOf(409),
                    e.getMessage());
            error.setProperty("msg", "User already exists");
        }

        if (e instanceof UsernameNotFoundException) {
            error = ProblemDetail.forStatusAndDetail(
                    HttpStatusCode.valueOf(404),
                    e.getMessage());
            error.setProperty("msg", "User not found");
        }

        if (e instanceof DisabledException) {
            error = ProblemDetail.forStatusAndDetail(
                    HttpStatusCode.valueOf(403),
                    e.getMessage());
            error.setProperty("msg", "Account is disabled. Please Verify your Account");
        }

        if (e instanceof BadCredentialsException) {
            error = ProblemDetail.forStatusAndDetail(
                    HttpStatusCode.valueOf(401),
                    e.getMessage());
            error.setProperty("msg", "Invalid username or password.");
        }

        if (e instanceof AccessDeniedException) {
            error = ProblemDetail.forStatusAndDetail(
                    HttpStatusCode.valueOf(403),
                    e.getMessage());
            error.setProperty("msg", "User is not authorized to access this resource");
        }

        if (e instanceof TransactionSystemException) {
            error = ProblemDetail.forStatusAndDetail(
                    HttpStatusCode.valueOf(400),
                    e.getMessage());
            error.setProperty("msg", "Invalid input");
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
