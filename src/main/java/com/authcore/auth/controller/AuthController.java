package com.authcore.auth.controller;

import org.springframework.web.bind.annotation.RestController;

import com.authcore.auth.dto.response.AuthResponse;
import com.authcore.auth.dto.response.MsgResponse;
import com.authcore.auth.dto.request.LoginRequest;
import com.authcore.auth.dto.request.RegisterRequest;
import com.authcore.auth.dto.request.ResetPasswordRequest;
import com.authcore.auth.service.AuthService;

import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;

import org.springframework.beans.propertyeditors.StringTrimmerEditor;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.http.ResponseEntity;
import org.springframework.lang.Nullable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;

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
    public ResponseEntity<MsgResponse> registerUser(
            @Valid @RequestBody RegisterRequest request) {
        return ResponseEntity.ok(authService.registerUser(request));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> loginUser(
            @Valid @RequestBody LoginRequest request, HttpServletResponse response) {
        return ResponseEntity.ok(authService.loginUser(request, response));
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refreshToken(@CookieValue(AuthService.REFRESH_COOKIE) String refreshToken) {
        return ResponseEntity.ok(authService.verifyRefreshToken(refreshToken));
    }

    @GetMapping("/verify-email")
    public ResponseEntity<MsgResponse> verifyEmail(@RequestParam @NotBlank @Email String email,
            @Nullable @RequestParam String token) {
        return ResponseEntity.ok(authService.verifyEmail(email, token));
    }

    @PostMapping("/reset-password")
    public ResponseEntity<MsgResponse> resetPassword(@RequestParam @NotBlank @Email String email,
            @Nullable @Valid @RequestBody ResetPasswordRequest request) {
        return ResponseEntity.ok(authService.resetPassword(email, request));
    }
}
