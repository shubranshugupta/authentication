package com.authcore.auth.auth;

import java.time.Duration;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.authcore.auth.common.AuthConfigProperties;
import com.authcore.auth.common.MsgResponse;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping(AuthController.PATH)
@RequiredArgsConstructor
public class AuthController {
    // Also the path of the refresh cookie: browsers only send it to paths under this one.
    static final String PATH = "/api/v1/auth";

    private static final String REFRESH_COOKIE = "refreshToken";

    // H2: these requests get the same answer whether or not the account exists,
    // is verified, or was sent a code a moment ago, so they can't be used to find
    // out which emails are registered.
    private static final String VERIFICATION_REQUESTED = "If an account with this email exists and isn't verified yet, a verification email has been sent.";
    private static final String RESET_REQUESTED = "If an account with this email exists, a password reset email has been sent.";

    private final AuthService authService;
    private final AuthConfigProperties authConfigProperties;

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

    @PostMapping("/email-verification")
    public ResponseEntity<MsgResponse> resendVerification(@Valid @RequestBody AccountEmailRequest request) {
        authService.resendVerification(request.getEmail());
        return message(VERIFICATION_REQUESTED);
    }

    /** A POST, so that link previews and prefetching can't use up the link (H4). */
    @PostMapping("/email-verification/confirm")
    public ResponseEntity<MsgResponse> verifyEmail(@Valid @RequestBody ConfirmEmailRequest request) {
        authService.verifyEmail(request.getToken());
        return message("Email verified successfully");
    }

    @PostMapping("/password-reset")
    public ResponseEntity<MsgResponse> requestPasswordReset(@Valid @RequestBody AccountEmailRequest request) {
        authService.requestPasswordReset(request.getEmail());
        return message(RESET_REQUESTED);
    }

    @PostMapping("/password-reset/confirm")
    public ResponseEntity<MsgResponse> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        authService.resetPassword(request.getEmail(), request.getOtp(), request.getPassword());
        return message("Password reset successfully");
    }

    private ResponseCookie refreshCookie(String refreshToken) {
        AuthConfigProperties.CookieConfigProperties cookie = authConfigProperties.getCookie();
        return ResponseCookie.from(REFRESH_COOKIE, refreshToken)
                .httpOnly(true)
                .secure(cookie.isSecure())
                .sameSite(cookie.getSameSite())
                .path(PATH)
                .maxAge(Duration.ofMillis(authConfigProperties.getToken().getRefreshExpiration()))
                .build();
    }

    private static ResponseEntity<MsgResponse> message(String msg) {
        return ResponseEntity.ok(MsgResponse.builder().msg(msg).build());
    }
}
