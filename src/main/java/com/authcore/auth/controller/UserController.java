package com.authcore.auth.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.lang.Nullable;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.authcore.auth.dto.request.DeleteAccountRequest;
import com.authcore.auth.dto.request.UpdateUserRequest;
import com.authcore.auth.dto.response.MsgResponse;
import com.authcore.auth.dto.response.UserResposne;
import com.authcore.auth.service.UserService;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;

@RestController
@RequestMapping("/user")
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;

    @GetMapping("/hello")
    public ResponseEntity<String> hello() {
        return ResponseEntity.ok("Hello World");
    }

    @GetMapping("/get-info")
    public ResponseEntity<UserResposne> getUserInfo(@RequestHeader("Authorization") String token) {
        return ResponseEntity.ok(userService.getUserInfo(token));
    }

    @PutMapping("/update-info")
    public ResponseEntity<MsgResponse> postMethodName(@RequestHeader("Authorization") String token,
            @Valid @RequestBody UpdateUserRequest newInfo) {
        return ResponseEntity.ok(userService.updateUserInfo(token, newInfo));
    }

    @DeleteMapping("/delete")
    public ResponseEntity<MsgResponse> getMethodName(@RequestHeader("Authorization") String token,
            @Nullable @Valid @RequestBody DeleteAccountRequest request) {
        return ResponseEntity.ok(userService.deleteUser(token, request));
    }

}
