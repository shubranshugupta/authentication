package com.authcore.auth.mfa;

import java.util.List;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.authcore.auth.common.MsgResponse;
import com.authcore.auth.security.UserPrincipal;
import com.authcore.auth.session.ClientInfo;

import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.RequiredArgsConstructor;

/**
 * The logged-in user's two-factor authentication: set up with {@code /setup}, then turned on
 * with the first code from the app ({@code /enable}).
 */
@RestController
@RequestMapping("/api/v1/users/me/2fa")
@RequiredArgsConstructor
@Tag(name = "Two-factor authentication", description = "An authenticator app's codes at every login, and recovery codes")
public class TwoFactorController {
    private final TwoFactorService twoFactor;

    @GetMapping
    public ResponseEntity<TwoFactorStatus> status(@AuthenticationPrincipal UserPrincipal me) {
        return ResponseEntity.ok(twoFactor.status(me.id()));
    }

    /** Needs the password. Returns a new secret for the app; nothing changes at login yet. */
    @PostMapping("/setup")
    public ResponseEntity<TotpSetup> setUp(@AuthenticationPrincipal UserPrincipal me,
            @Valid @RequestBody PasswordRequest request, HttpServletRequest http) {
        return ResponseEntity.ok(twoFactor.setUp(me.id(), request.currentPassword(), ClientInfo.of(http)));
    }

    /** Turns it on with the first code from the app. Returns the recovery codes, shown this once. */
    @PostMapping("/enable")
    public ResponseEntity<RecoveryCodesResponse> enable(@AuthenticationPrincipal UserPrincipal me,
            @Valid @RequestBody CodeRequest request, HttpServletRequest http) {
        return ResponseEntity.ok(new RecoveryCodesResponse(twoFactor.enable(me.id(), request.code(), ClientInfo.of(http))));
    }

    /** Needs the password and a code from the app (or a recovery code). */
    @PostMapping("/disable")
    public ResponseEntity<MsgResponse> disable(@AuthenticationPrincipal UserPrincipal me,
            @Valid @RequestBody PasswordAndCodeRequest request, HttpServletRequest http) {
        twoFactor.disable(me.id(), request.currentPassword(), request.code(), ClientInfo.of(http));
        return ResponseEntity.ok(MsgResponse.builder().msg("Two-factor authentication is off.").build());
    }

    /** New recovery codes; the old ones stop working. Needs the password and a code. */
    @PostMapping("/recovery-codes")
    public ResponseEntity<RecoveryCodesResponse> newRecoveryCodes(@AuthenticationPrincipal UserPrincipal me,
            @Valid @RequestBody PasswordAndCodeRequest request, HttpServletRequest http) {
        return ResponseEntity.ok(new RecoveryCodesResponse(
                twoFactor.newRecoveryCodes(me.id(), request.currentPassword(), request.code(), ClientInfo.of(http))));
    }

    public record PasswordRequest(@NotBlank @Size(max = 256) String currentPassword) {
        @Override
        public String toString() {
            return "PasswordRequest[]";
        }
    }

    /** @param code the 6 digits from the app */
    public record CodeRequest(@NotBlank @Size(max = 32) String code) {
        @Override
        public String toString() {
            return "CodeRequest[]";
        }
    }

    /** @param code the 6 digits from the app, or a recovery code */
    public record PasswordAndCodeRequest(@NotBlank @Size(max = 256) String currentPassword,
            @NotBlank @Size(max = 32) String code) {
        @Override
        public String toString() {
            return "PasswordAndCodeRequest[]";
        }
    }

    /** Each works once instead of a code from the app. Shown once; only hashes are kept. */
    public record RecoveryCodesResponse(List<String> recoveryCodes) {
        @Override
        public String toString() {
            return "RecoveryCodesResponse[...]";
        }
    }
}
