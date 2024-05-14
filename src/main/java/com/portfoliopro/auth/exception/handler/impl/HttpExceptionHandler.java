package com.portfoliopro.auth.exception.handler.impl;

import org.springframework.http.HttpStatusCode;
import org.springframework.http.ProblemDetail;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

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
public class HttpExceptionHandler implements AuthExceptionHandler {
    private AuthExceptionHandler nextHandler;

    @Override
    public ProblemDetail handle(Exception e) {
        ProblemDetail error = null;

        if (e instanceof HttpMediaTypeNotSupportedException) {
            error = ProblemDetail.forStatusAndDetail(
                    HttpStatusCode.valueOf(415),
                    e.getMessage());
            error.setProperty("msg", "Unsupported media type");
        }

        if (e instanceof HttpRequestMethodNotSupportedException) {
            error = ProblemDetail.forStatusAndDetail(
                    HttpStatusCode.valueOf(405),
                    e.getMessage());
            error.setProperty("msg", "Method not allowed");
        }

        if (e instanceof NoResourceFoundException) {
            error = ProblemDetail.forStatusAndDetail(
                    HttpStatusCode.valueOf(404),
                    e.getMessage());
            error.setProperty("msg", "Resource not found");
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
