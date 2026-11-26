package com.authcore.auth.common;

import java.util.LinkedHashMap;
import java.util.Map;

import org.jspecify.annotations.Nullable;
import org.springframework.beans.TypeMismatchException;
import org.springframework.context.MessageSourceResolvable;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.LockedException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingRequestCookieException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.ServletRequestBindingException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.method.annotation.HandlerMethodValidationException;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import com.authcore.auth.ratelimit.TooManyRequestsException;
import com.authcore.auth.security.InvalidTokenException;
import com.authcore.auth.security.TokenExpireException;
import com.authcore.auth.security.WrongPasswordException;
import com.authcore.auth.session.SessionNotFoundException;
import com.authcore.auth.token.InvalidCodeException;
import com.authcore.auth.token.TokenAlreadyExistsException;
import com.authcore.auth.user.admin.AdminActionRefusedException;
import com.authcore.auth.user.UserAlreadyExistsException;
import com.authcore.auth.user.UserNotFoundException;

import lombok.extern.slf4j.Slf4j;

/**
 * Turns every exception into a ProblemDetail (RFC 9457) with two extra properties:
 * "code" ({@link ErrorCode}, stable) and "msg" (a short text). Spring's own exceptions
 * are handled by the base class, which also sets headers such as Allow.
 *
 * <p>An exception's message is only sent if this application wrote it. Anything
 * unexpected gets a generic text, and its details stay in the server log (H2).
 */
@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

    // ---- login and tokens ----------------------------------------------------------

    @ExceptionHandler
    ProblemDetail handle(InsufficientAuthenticationException e) {
        return problem(ErrorCode.AUTHENTICATION_REQUIRED, e.getMessage());
    }

    @ExceptionHandler
    ProblemDetail handle(BadCredentialsException e) {
        return problem(ErrorCode.INVALID_CREDENTIALS, e.getMessage());
    }

    @ExceptionHandler
    ProblemDetail handle(DisabledException e) {
        return problem(ErrorCode.ACCOUNT_DISABLED, e.getMessage());
    }

    @ExceptionHandler
    ProblemDetail handle(LockedException e) {
        return problem(ErrorCode.ACCOUNT_LOCKED, "An administrator locked this account.");
    }

    @ExceptionHandler
    ProblemDetail handle(WrongPasswordException e) {
        return problem(ErrorCode.WRONG_PASSWORD, e.getMessage());
    }

    @ExceptionHandler
    ProblemDetail handle(AccessDeniedException e) {
        return problem(ErrorCode.ACCESS_DENIED, e.getMessage());
    }

    @ExceptionHandler
    ProblemDetail handle(InvalidTokenException e) {
        return problem(ErrorCode.INVALID_TOKEN, e.getMessage());
    }

    @ExceptionHandler
    ProblemDetail handle(TokenExpireException e) {
        return problem(ErrorCode.TOKEN_EXPIRED, e.getMessage());
    }

    @ExceptionHandler
    ProblemDetail handle(InvalidCodeException e) {
        return problem(ErrorCode.INVALID_CODE, e.getMessage());
    }

    @ExceptionHandler
    ProblemDetail handle(TokenAlreadyExistsException e) {
        return problem(ErrorCode.TOKEN_ALREADY_EXISTS, e.getMessage());
    }

    // ---- users and sessions ---------------------------------------------------------------------

    @ExceptionHandler
    ProblemDetail handle(UserAlreadyExistsException e) {
        return problem(ErrorCode.USER_ALREADY_EXISTS, e.getMessage());
    }

    @ExceptionHandler
    ProblemDetail handle(UserNotFoundException e) {
        return problem(ErrorCode.USER_NOT_FOUND, e.getMessage());
    }

    @ExceptionHandler
    ProblemDetail handle(AdminActionRefusedException e) {
        return problem(ErrorCode.ADMIN_ACTION_REFUSED, e.getMessage());
    }

    @ExceptionHandler
    ProblemDetail handle(SessionNotFoundException e) {
        return problem(ErrorCode.SESSION_NOT_FOUND, e.getMessage());
    }

    // ---- rate limits ---------------------------------------------------------------

    @ExceptionHandler
    ResponseEntity<ProblemDetail> handle(TooManyRequestsException e) {
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                .header(HttpHeaders.RETRY_AFTER, String.valueOf(e.getRetryAfterSeconds()))
                .body(problem(ErrorCode.TOO_MANY_REQUESTS, e.getMessage()));
    }

    // ---- everything else -----------------------------------------------------------

    @ExceptionHandler
    ProblemDetail handle(Exception e) {
        log.error(e.getMessage(), e);
        return problem(ErrorCode.INTERNAL_ERROR, "An unexpected error occurred.");
    }

    // ---- invalid input (H1) --------------------------------------------------------
    // "errors" maps each field or parameter to what's wrong with it, e.g.
    // {"password": "must be at least 12 characters"}.

    @Override
    protected @Nullable ResponseEntity<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException e,
            HttpHeaders headers, HttpStatusCode status, WebRequest request) {
        Map<String, String> errors = new LinkedHashMap<>();
        for (FieldError field : e.getBindingResult().getFieldErrors())
            addError(errors, field.getField(), field);
        return handleExceptionInternal(e, invalidInput(errors), headers, status, request);
    }

    @Override
    protected @Nullable ResponseEntity<Object> handleHandlerMethodValidationException(
            HandlerMethodValidationException e, HttpHeaders headers, HttpStatusCode status, WebRequest request) {
        if (e.isForReturnValue())
            return super.handleHandlerMethodValidationException(e, headers, status, request);
        Map<String, String> errors = new LinkedHashMap<>();
        e.getParameterValidationResults().forEach(result -> {
            String parameter = result.getMethodParameter().getParameterName();
            for (MessageSourceResolvable problem : result.getResolvableErrors())
                addError(errors, problem instanceof FieldError field ? field.getField() : parameter, problem);
        });
        return handleExceptionInternal(e, invalidInput(errors), headers, status, request);
    }

    @Override
    protected @Nullable ResponseEntity<Object> handleHttpMessageNotReadable(HttpMessageNotReadableException e,
            HttpHeaders headers, HttpStatusCode status, WebRequest request) {
        return handleExceptionInternal(e,
                problem(ErrorCode.MALFORMED_BODY, "The request body is missing or isn't valid JSON."),
                headers, status, request);
    }

    @Override
    protected @Nullable ResponseEntity<Object> handleMissingServletRequestParameter(
            MissingServletRequestParameterException e, HttpHeaders headers, HttpStatusCode status,
            WebRequest request) {
        return handleExceptionInternal(e,
                problem(ErrorCode.MISSING_PARAMETER, "Required parameter '" + e.getParameterName() + "' is missing."),
                headers, status, request);
    }

    @Override
    protected @Nullable ResponseEntity<Object> handleTypeMismatch(TypeMismatchException e, HttpHeaders headers,
            HttpStatusCode status, WebRequest request) {
        String name = e instanceof MethodArgumentTypeMismatchException argument ? argument.getName()
                : e.getPropertyName();
        return handleExceptionInternal(e,
                problem(ErrorCode.INVALID_PARAMETER, "Parameter '" + name + "' has an invalid value."),
                headers, status, request);
    }

    @Override
    protected @Nullable ResponseEntity<Object> handleServletRequestBindingException(ServletRequestBindingException e,
            HttpHeaders headers, HttpStatusCode status, WebRequest request) {
        if (e instanceof MissingRequestCookieException cookie)
            return handleExceptionInternal(e,
                    problem(ErrorCode.MISSING_COOKIE, "Required cookie '" + cookie.getCookieName() + "' is missing."),
                    headers, status, request);
        return super.handleServletRequestBindingException(e, headers, status, request);
    }

    /** Every exception the base class handles ends up here. */
    @Override
    protected @Nullable ResponseEntity<Object> handleExceptionInternal(Exception e, @Nullable Object body,
            HttpHeaders headers, HttpStatusCode status, WebRequest request) {
        if (status.is5xxServerError()) {
            log.error(e.getMessage(), e);
            body = problem(ErrorCode.forStatus(status), "An unexpected error occurred.");
            ((ProblemDetail) body).setStatus(status.value());
        }
        ResponseEntity<Object> response = super.handleExceptionInternal(e, body, headers, status, request);
        if (response != null && response.getBody() instanceof ProblemDetail problem
                && (problem.getProperties() == null || !problem.getProperties().containsKey("code")))
            addCode(problem, ErrorCode.forStatus(status));
        return response;
    }

    // ---- helpers -------------------------------------------------------------------

    private static ProblemDetail problem(ErrorCode code, String detail) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(code.status, detail);
        addCode(problem, code);
        return problem;
    }

    private static void addCode(ProblemDetail problem, ErrorCode code) {
        problem.setProperty("code", code.name());
        problem.setProperty("msg", code.msg);
    }

    private static ProblemDetail invalidInput(Map<String, String> errors) {
        ProblemDetail problem = problem(ErrorCode.INVALID_INPUT, "One or more fields are invalid.");
        problem.setProperty("errors", errors);
        return problem;
    }

    private static void addError(Map<String, String> errors, String name, MessageSourceResolvable error) {
        errors.merge(name, String.valueOf(error.getDefaultMessage()), (a, b) -> a + "; " + b);
    }
}
