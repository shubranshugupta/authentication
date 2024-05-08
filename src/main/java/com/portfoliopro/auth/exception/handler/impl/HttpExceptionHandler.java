package com.portfoliopro.auth.exception.handler.impl;

import org.springframework.http.HttpStatusCode;
import org.springframework.http.ProblemDetail;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;

import com.portfoliopro.auth.exception.handler.AuthExceptionHandler;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class HttpExceptionHandler implements AuthExceptionHandler {
    private AuthExceptionHandler nextHandler;

    @Override
    public ProblemDetail handle(Exception e) {
        ProblemDetail error = null;
        // e.printStackTrace();

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
