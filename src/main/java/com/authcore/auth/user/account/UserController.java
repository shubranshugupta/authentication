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
@Tag(name = "My account", description = "The logged-in user's profile, password and account deletion")
public class UserController {
    private final UserService userService;
    private final AuthService authService;
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
                request.newPassword(), ClientInfo.of(http).ip());
        return ResponseEntity.ok(AuthResponse.builder().accessToken(accessToken).build());
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
