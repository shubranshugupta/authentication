package com.authcore.auth.controller;

import org.jspecify.annotations.Nullable;
import java.time.Duration;

import org.springframework.beans.propertyeditors.StringTrimmerEditor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.authcore.auth.config.properties.AuthConfigProperties;
import com.authcore.auth.dto.request.LoginRequest;
import com.authcore.auth.dto.request.RegisterRequest;
import com.authcore.auth.dto.request.ResetPasswordRequest;
import com.authcore.auth.dto.response.AuthResponse;
import com.authcore.auth.dto.response.MsgResponse;
import com.authcore.auth.service.AuthService;
import com.authcore.auth.service.TokenPair;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
    private static final String REFRESH_COOKIE = "refreshToken";
    // Browsers only send the cookie to paths under this one, so it reaches
    // /auth/refresh and nothing else. Must change if the auth endpoints move (A6).
    private static final String REFRESH_COOKIE_PATH = "/auth";

    // H2: these requests get the same answer whether or not the account exists,
    // is verified, or already has an active code, so they can't be used to find
    // out which emails are registered.
    private static final String VERIFICATION_REQUESTED = "If an account with this email exists and isn't verified yet, a verification email has been sent.";
    private static final String RESET_REQUESTED = "If an account with this email exists, a password reset email has been sent.";

    private final AuthService authService;
    private final AuthConfigProperties authConfigProperties;

    /**
     * Trims the "email" query parameters before they're validated: @Email rejects
     * spaces, and the services only normalize after validation. (Emails in JSON
     * bodies: NormalizedEmailDeserializer.)
     */
    @InitBinder("email")
    void trimEmailParameters(WebDataBinder binder) {
        binder.registerCustomEditor(String.class, new StringTrimmerEditor(false));
    }

    @PostMapping("/register")
    public ResponseEntity<MsgResponse> register(@Valid @RequestBody RegisterRequest request) {
        authService.register(request);
        return message("Verification email sent");
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        TokenPair tokens = authService.login(request.getEmail(), request.getPassword());
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, refreshCookie(tokens.refreshToken()).toString())
                .body(new AuthResponse(tokens.accessToken()));
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(@CookieValue(REFRESH_COOKIE) String refreshToken) {
        return ResponseEntity.ok(new AuthResponse(authService.refresh(refreshToken)));
    }

    @GetMapping("/verify-email")
    public ResponseEntity<MsgResponse> verifyEmail(@RequestParam @NotBlank @Email String email,
            @RequestParam(required = false) @Nullable String token) {
        if (token == null) {
            authService.resendVerification(email);
            return message(VERIFICATION_REQUESTED);
        }
        authService.verifyEmail(email, token);
        return message("Email verified successfully");
    }

    @PostMapping("/reset-password")
    public ResponseEntity<MsgResponse> resetPassword(@RequestParam @NotBlank @Email String email,
            @Valid @RequestBody(required = false) @Nullable ResetPasswordRequest request) {
        if (request == null) {
            authService.requestPasswordReset(email);
            return message(RESET_REQUESTED);
        }
        authService.resetPassword(email, String.valueOf(request.getOtp()), request.getPassword());
        return message("Password reset successfully");
    }

    private ResponseCookie refreshCookie(String refreshToken) {
        AuthConfigProperties.CookieConfigProperties cookie = authConfigProperties.getCookie();
        return ResponseCookie.from(REFRESH_COOKIE, refreshToken)
                .httpOnly(true)
                .secure(cookie.isSecure())
                .sameSite(cookie.getSameSite())
                .path(REFRESH_COOKIE_PATH)
                .maxAge(Duration.ofMillis(authConfigProperties.getToken().getRefreshExpiration()))
                .build();
    }

    private static ResponseEntity<MsgResponse> message(String msg) {
        return ResponseEntity.ok(MsgResponse.builder().msg(msg).build());
    }
}
