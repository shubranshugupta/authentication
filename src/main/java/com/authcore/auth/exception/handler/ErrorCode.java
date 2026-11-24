package com.authcore.auth.exception.handler;

import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;

/**
 * The "code" of every error response. Part of the API: clients decide what to do by
 * this, so a code must not be renamed. The "msg" and "detail" texts may change.
 */
public enum ErrorCode {
    // input
    BAD_REQUEST(HttpStatus.BAD_REQUEST, "Bad request"),
    INVALID_INPUT(HttpStatus.BAD_REQUEST, "Invalid input"),
    MALFORMED_BODY(HttpStatus.BAD_REQUEST, "Malformed request body"),
    MISSING_PARAMETER(HttpStatus.BAD_REQUEST, "Missing parameter"),
    INVALID_PARAMETER(HttpStatus.BAD_REQUEST, "Invalid parameter"),
    MISSING_COOKIE(HttpStatus.BAD_REQUEST, "Missing cookie"),
    NOT_FOUND(HttpStatus.NOT_FOUND, "Resource not found"),
    METHOD_NOT_ALLOWED(HttpStatus.METHOD_NOT_ALLOWED, "Method not allowed"),
    NOT_ACCEPTABLE(HttpStatus.NOT_ACCEPTABLE, "Not acceptable"),
    UNSUPPORTED_MEDIA_TYPE(HttpStatus.UNSUPPORTED_MEDIA_TYPE, "Unsupported media type"),

    // login and tokens
    AUTHENTICATION_REQUIRED(HttpStatus.UNAUTHORIZED, "JWT token is missing"),
    INVALID_CREDENTIALS(HttpStatus.UNAUTHORIZED, "Invalid username or password."),
    INVALID_TOKEN(HttpStatus.UNAUTHORIZED, "Invalid Token"),
    TOKEN_EXPIRED(HttpStatus.UNAUTHORIZED, "Token has expired"),
    ACCOUNT_DISABLED(HttpStatus.FORBIDDEN, "Account is disabled. Please Verify your Account"),
    ACCESS_DENIED(HttpStatus.FORBIDDEN, "User is not authorized to access this resource"),
    TOKEN_ALREADY_EXISTS(HttpStatus.CONFLICT, "Token already exists"),

    // users
    USER_NOT_FOUND(HttpStatus.NOT_FOUND, "User not found"),
    USER_ALREADY_EXISTS(HttpStatus.CONFLICT, "User already exists"),

    INTERNAL_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, "An unexpected error occurred");

    final HttpStatus status;
    final String msg;

    ErrorCode(HttpStatus status, String msg) {
        this.status = status;
        this.msg = msg;
    }

    /** For framework errors that have no code of their own. */
    static ErrorCode forStatus(HttpStatusCode status) {
        return switch (status.value()) {
            case 404 -> NOT_FOUND;
            case 405 -> METHOD_NOT_ALLOWED;
            case 406 -> NOT_ACCEPTABLE;
            case 415 -> UNSUPPORTED_MEDIA_TYPE;
            default -> status.is4xxClientError() ? BAD_REQUEST : INTERNAL_ERROR;
        };
    }
}
