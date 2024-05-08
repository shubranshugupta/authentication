package com.portfoliopro.auth.controller;

import org.springframework.web.bind.annotation.RestController;

import com.portfoliopro.auth.dto.AuthResponse;
import com.portfoliopro.auth.dto.LoginRequest;
import com.portfoliopro.auth.dto.RegisterRequest;
import com.portfoliopro.auth.service.AuthService;

import lombok.RequiredArgsConstructor;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.GetMapping;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> registerUser(
            @RequestBody RegisterRequest request) {
        return ResponseEntity.ok(authService.registerUser(request));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> loginUser(
            @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.loginUser(request));
    }

    // todo: add logout endpoint

    @GetMapping("/hello")
    public ResponseEntity<String> hello() {
        return ResponseEntity.ok("Hello World");
    }

}
