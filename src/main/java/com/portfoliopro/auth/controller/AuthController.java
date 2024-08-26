package com.portfoliopro.auth.controller;

import org.springframework.web.bind.annotation.RestController;

import com.portfoliopro.auth.dto.response.AuthResponse;
import com.portfoliopro.auth.dto.response.MsgResponse;
import com.portfoliopro.auth.dto.request.LoginRequest;
import com.portfoliopro.auth.dto.request.RegisterRequest;
import com.portfoliopro.auth.dto.request.ResetPasswordRequest;
import com.portfoliopro.auth.service.AuthService;

import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

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

    @PostMapping("/register")
    public ResponseEntity<MsgResponse> registerUser(
            @RequestBody RegisterRequest request) {
        return ResponseEntity.ok(authService.registerUser(request));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> loginUser(
            @RequestBody LoginRequest request, HttpServletResponse response) {
        return ResponseEntity.ok(authService.loginUser(request, response));
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refreshToken(@CookieValue("refreshToken") String refreshToken) {
        return ResponseEntity.ok(authService.verifyRefreshToken(refreshToken));
    }

    @GetMapping("/verify-email")
    public ResponseEntity<MsgResponse> verifyEmail(@RequestParam String email, @Nullable @RequestParam String token) {
        return ResponseEntity.ok(authService.verifyEmail(email, token));
    }

    @PostMapping("/reset-password")
    public ResponseEntity<MsgResponse> resetPassword(@RequestParam String email,
            @Nullable @RequestBody ResetPasswordRequest request) {
        return ResponseEntity.ok(authService.resetPassword(email, request));
    }
}
