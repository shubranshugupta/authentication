package com.portfoliopro.auth.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.lang.Nullable;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.portfoliopro.auth.dto.request.DeleteAccountRequest;
import com.portfoliopro.auth.dto.request.UpdateUserRequest;
import com.portfoliopro.auth.dto.response.MsgResponse;
import com.portfoliopro.auth.dto.response.UserResposne;
import com.portfoliopro.auth.service.UserService;

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
            @RequestBody UpdateUserRequest newInfo) {
        return ResponseEntity.ok(userService.updateUserInfo(token, newInfo));
    }

    @DeleteMapping("/delete")
    public ResponseEntity<MsgResponse> getMethodName(@RequestHeader("Authorization") String token,
            @Nullable @RequestBody DeleteAccountRequest request) {
        return ResponseEntity.ok(userService.deleteUser(token, request));
    }

}
