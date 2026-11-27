package com.authcore.auth.user.account;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.authcore.auth.auth.AuthResponse;
import com.authcore.auth.auth.AuthService;
import com.authcore.auth.common.MsgResponse;
import com.authcore.auth.ratelimit.RateLimit;
import com.authcore.auth.ratelimit.RateLimiter;
import com.authcore.auth.security.UserPrincipal;
import com.authcore.auth.session.ClientInfo;

import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/v1/users/me")
@RequiredArgsConstructor
@Tag(name = "My account", description = "The logged-in user's profile, password, email and account deletion")
public class UserController {
    private final UserService userService;
    private final AuthService authService;
    private final EmailChangeService emailChangeService;
    private final RateLimiter rateLimiter;

    @GetMapping
    public ResponseEntity<UserResponse> getUserInfo(@AuthenticationPrincipal UserPrincipal me) {
        return ResponseEntity.ok(userService.getProfile(me.id()));
    }

    @PatchMapping
    public ResponseEntity<MsgResponse> updateUser(@AuthenticationPrincipal UserPrincipal me,
            @Valid @RequestBody UpdateUserRequest newInfo) {
        userService.updateProfile(me.id(), newInfo.getFirstName(), newInfo.getLastName());
        return message("User info updated successfully.");
    }

    /**
     * Needs the current password. Logs out every other device; this one gets a new access
     * token, because the old one stops working.
     */
    @PutMapping("/password")
    public ResponseEntity<AuthResponse> changePassword(@AuthenticationPrincipal UserPrincipal me,
            @Valid @RequestBody ChangePasswordRequest request, HttpServletRequest http) {
        String accessToken = authService.changePassword(me.id(), me.sessionId(), request.currentPassword(),
                request.newPassword(), ClientInfo.of(http));
        return ResponseEntity.ok(AuthResponse.builder().accessToken(accessToken).build());
    }

    /** Needs the current password. Sends a code to the new address; nothing changes yet. */
    @PostMapping("/email")
    public ResponseEntity<MsgResponse> requestEmailChange(@AuthenticationPrincipal UserPrincipal me,
            @Valid @RequestBody ChangeEmailRequest request, HttpServletRequest http) {
        rateLimiter.acquire(RateLimit.EMAIL_CHANGE_EMAIL_PER_USER.forUser(me.id()));
        emailChangeService.request(me.id(), request.currentPassword(), request.newEmail(), ClientInfo.of(http));
        return message("A code was sent to the new address.");
    }

    /**
     * Changes the email to the address the code was sent to. The old address gets a link
     * that changes it back for 7 days. Every device stays logged in.
     */
    @PostMapping("/email/confirm")
    public ResponseEntity<MsgResponse> confirmEmailChange(@AuthenticationPrincipal UserPrincipal me,
            @Valid @RequestBody ConfirmEmailChangeRequest request, HttpServletRequest http) {
        emailChangeService.confirm(me.id(), request.otp(), ClientInfo.of(http));
        return message("Email changed.");
    }

    @PostMapping("/deletion")
    public ResponseEntity<MsgResponse> requestDeletion(@AuthenticationPrincipal UserPrincipal me) {
        rateLimiter.acquire(RateLimit.DELETION_EMAIL_PER_USER.forUser(me.id()));
        userService.requestDeletion(me.id());
        return message("Delete account email sent.");
    }

    /** A POST, because some proxies and clients drop the body of a DELETE (H8). */
    @PostMapping("/deletion/confirm")
    public ResponseEntity<MsgResponse> deleteUser(@AuthenticationPrincipal UserPrincipal me,
            @Valid @RequestBody DeleteAccountRequest request) {
        userService.confirmDeletion(me.id(), request.getOtp(), request.getPassword());
        return message("User deleted successfully.");
    }

    private static ResponseEntity<MsgResponse> message(String msg) {
        return ResponseEntity.ok(MsgResponse.builder().msg(msg).build());
    }
}
