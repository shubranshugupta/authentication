package com.authcore.auth.auth;

import java.time.Duration;

import org.jspecify.annotations.Nullable;
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
import com.authcore.auth.ratelimit.RateLimit;
import com.authcore.auth.ratelimit.RateLimiter;
import com.authcore.auth.session.ClientInfo;
import com.authcore.auth.session.DeviceService;
import com.authcore.auth.user.account.EmailChangeService;

import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping(AuthController.PATH)
@RequiredArgsConstructor
@Tag(name = "Auth", description = "Registration, login, refresh, logout, email verification, password reset and undoing an email change")
@SecurityRequirements // no access token needed
public class AuthController {
    // Also the path of the refresh cookie: browsers only send it to paths under this one.
    static final String PATH = "/api/v1/auth";

    private static final String REFRESH_COOKIE = "refreshToken";
    // Kept across logouts: it says which browser this is, not who is logged in (F5).
    private static final String DEVICE_COOKIE = "deviceId";

    // H2: these requests get the same answer whether or not the account exists,
    // is verified, or was sent a code a moment ago, so they can't be used to find
    // out which emails are registered.
    private static final String VERIFICATION_REQUESTED = "If an account with this email exists and isn't verified yet, a verification email has been sent.";
    private static final String RESET_REQUESTED = "If an account with this email exists, a password reset email has been sent.";

    private final AuthService authService;
    private final EmailChangeService emailChangeService;
    private final RateLimiter rateLimiter;
    private final AuthConfigProperties authConfigProperties;

    @PostMapping("/register")
    public ResponseEntity<MsgResponse> register(@Valid @RequestBody RegisterRequest request, HttpServletRequest http) {
        rateLimiter.acquire(RateLimit.REGISTRATION_PER_IP.forIp(http.getRemoteAddr()));
        authService.register(request);
        return message("Verification email sent");
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request,
            @CookieValue(name = DEVICE_COOKIE, required = false) @Nullable String deviceId, HttpServletRequest http) {
        LoginResult login = authService.login(request.getEmail(), request.getPassword(), ClientInfo.of(http), deviceId);
        return tokens(login.tokens(), cookie(DEVICE_COOKIE, login.deviceId(), DeviceService.REMEMBERED_FOR));
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(@CookieValue(REFRESH_COOKIE) String refreshToken,
            HttpServletRequest http) {
        return tokens(authService.refresh(refreshToken, ClientInfo.of(http)));
    }

    /** Works with any cookie, or none: whoever logs out only wants to be logged out. */
    @PostMapping("/logout")
    public ResponseEntity<MsgResponse> logout(
            @CookieValue(name = REFRESH_COOKIE, required = false) @Nullable String refreshToken) {
        if (refreshToken != null)
            authService.logout(refreshToken);
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, refreshCookie("", Duration.ZERO).toString()) // deletes it
                .body(MsgResponse.builder().msg("Logged out").build());
    }

    @PostMapping("/email-verification")
    public ResponseEntity<MsgResponse> resendVerification(@Valid @RequestBody AccountEmailRequest request,
            HttpServletRequest http) {
        rateLimiter.acquire(RateLimit.VERIFICATION_EMAIL_PER_IP.forIp(http.getRemoteAddr()),
                RateLimit.VERIFICATION_EMAIL_PER_ACCOUNT.forAccount(request.getEmail()));
        authService.resendVerification(request.getEmail());
        return message(VERIFICATION_REQUESTED);
    }

    /** A POST, so that link previews and prefetching can't use up the link (H4). */
    @PostMapping("/email-verification/confirm")
    public ResponseEntity<MsgResponse> verifyEmail(@Valid @RequestBody ConfirmEmailRequest request,
            HttpServletRequest http) {
        rateLimiter.acquire(RateLimit.VERIFICATION_CONFIRM_PER_IP.forIp(http.getRemoteAddr()));
        authService.verifyEmail(request.getToken());
        return message("Email verified successfully");
    }

    @PostMapping("/password-reset")
    public ResponseEntity<MsgResponse> requestPasswordReset(@Valid @RequestBody AccountEmailRequest request,
            HttpServletRequest http) {
        rateLimiter.acquire(RateLimit.RESET_EMAIL_PER_IP.forIp(http.getRemoteAddr()),
                RateLimit.RESET_EMAIL_PER_ACCOUNT.forAccount(request.getEmail()));
        authService.requestPasswordReset(request.getEmail());
        return message(RESET_REQUESTED);
    }

    @PostMapping("/password-reset/confirm")
    public ResponseEntity<MsgResponse> resetPassword(@Valid @RequestBody ResetPasswordRequest request,
            HttpServletRequest http) {
        String ip = http.getRemoteAddr();
        rateLimiter.acquire(RateLimit.RESET_CONFIRM_PER_IP.forIp(ip),
                RateLimit.RESET_CONFIRM_PER_IP_AND_ACCOUNT.forIpAndAccount(ip, request.getEmail()));
        authService.resetPassword(request.getEmail(), request.getOtp(), request.getPassword(), ClientInfo.of(http));
        return message("Password reset successfully");
    }

    /**
     * From the link sent to the old address after an email change: changes the email back,
     * sets a new password and logs out every device. A POST, like email verification (H4).
     */
    @PostMapping("/email-change/undo")
    public ResponseEntity<MsgResponse> undoEmailChange(@Valid @RequestBody UndoEmailChangeRequest request,
            HttpServletRequest http) {
        rateLimiter.acquire(RateLimit.EMAIL_CHANGE_UNDO_PER_IP.forIp(http.getRemoteAddr()));
        emailChangeService.undo(request.token(), request.password(), ClientInfo.of(http));
        return message("Your email was changed back and your password was reset. Every device was logged out.");
    }

    private ResponseEntity<AuthResponse> tokens(TokenPair tokens, ResponseCookie... more) {
        ResponseEntity.BodyBuilder response = ResponseEntity.ok();
        for (ResponseCookie cookie : more)
            response.header(HttpHeaders.SET_COOKIE, cookie.toString());
        if (tokens.refreshToken() != null)
            response.header(HttpHeaders.SET_COOKIE,
                    refreshCookie(tokens.refreshToken(), tokens.refreshValidFor()).toString());
        return response.body(new AuthResponse(tokens.accessToken()));
    }

    private ResponseCookie refreshCookie(String refreshToken, Duration maxAge) {
        return cookie(REFRESH_COOKIE, refreshToken, maxAge);
    }

    private ResponseCookie cookie(String name, String value, Duration maxAge) {
        AuthConfigProperties.CookieConfigProperties cookie = authConfigProperties.getCookie();
        return ResponseCookie.from(name, value)
                .httpOnly(true)
                .secure(cookie.isSecure())
                .sameSite(cookie.getSameSite())
                .path(PATH)
                .maxAge(maxAge)
                .build();
    }

    private static ResponseEntity<MsgResponse> message(String msg) {
        return ResponseEntity.ok(MsgResponse.builder().msg(msg).build());
    }
}
