package com.authcore.auth.exception.handler.impl;

import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.context.MessageSourceResolvable;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ProblemDetail;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.validation.FieldError;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingRequestCookieException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.method.annotation.HandlerMethodValidationException;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import com.authcore.auth.exception.handler.AuthExceptionHandler;

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

        // Invalid input (H1). "errors" maps each field or parameter to what's wrong,
        // e.g. {"password": "must be at least 12 characters"}.
        if (e instanceof MethodArgumentNotValidException invalid) {
            error = badRequest("Invalid input", "One or more fields are invalid.");
            error.setProperty("errors", fieldErrors(invalid.getBindingResult().getFieldErrors()));
        }

        if (e instanceof HandlerMethodValidationException invalid) {
            error = badRequest("Invalid input", "One or more fields are invalid.");
            Map<String, String> errors = new LinkedHashMap<>();
            invalid.getParameterValidationResults().forEach(result -> {
                String parameter = result.getMethodParameter().getParameterName();
                for (MessageSourceResolvable problem : result.getResolvableErrors()) {
                    String name = problem instanceof FieldError field ? field.getField() : parameter;
                    errors.merge(name, problem.getDefaultMessage(), (a, b) -> a + "; " + b);
                }
            });
            error.setProperty("errors", errors);
        }

        if (e instanceof HttpMessageNotReadableException) {
            error = badRequest("Malformed request body", "The request body is missing or isn't valid JSON.");
        }

        if (e instanceof MissingServletRequestParameterException missing) {
            error = badRequest("Missing parameter", "Required parameter '" + missing.getParameterName() + "' is missing.");
        }

        if (e instanceof MethodArgumentTypeMismatchException mismatch) {
            error = badRequest("Invalid parameter", "Parameter '" + mismatch.getName() + "' has an invalid value.");
        }

        if (e instanceof NoResourceFoundException) {
            error = ProblemDetail.forStatusAndDetail(
                    HttpStatusCode.valueOf(404),
                    e.getMessage());
            error.setProperty("msg", "Resource not found");
        }

        if (e instanceof MissingRequestCookieException) {
            error = ProblemDetail.forStatusAndDetail(
                    HttpStatusCode.valueOf(400),
                    e.getMessage());
            error.setProperty("msg", "Missing cookie");
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

    private static ProblemDetail badRequest(String msg, String detail) {
        ProblemDetail error = ProblemDetail.forStatusAndDetail(HttpStatusCode.valueOf(400), detail);
        error.setProperty("msg", msg);
        return error;
    }

    private static Map<String, String> fieldErrors(Iterable<FieldError> fieldErrors) {
        Map<String, String> errors = new LinkedHashMap<>();
        for (FieldError field : fieldErrors)
            errors.merge(field.getField(), field.getDefaultMessage(), (a, b) -> a + "; " + b);
        return errors;
    }
}
