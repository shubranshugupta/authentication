package com.portfoliopro.auth.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.portfoliopro.auth.dto.request.UpdateUserRequest;
import com.portfoliopro.auth.dto.response.MsgResponse;
import com.portfoliopro.auth.dto.response.UserResposne;
import com.portfoliopro.auth.service.UserService;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
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

    @GetMapping("/getInfo")
    public ResponseEntity<UserResposne> getUserInfo(@RequestHeader("Authorization") String token) {
        return ResponseEntity.ok(userService.getUserInfo(token));
    }

    @PostMapping("/updateInfo")
    public ResponseEntity<MsgResponse> postMethodName(@RequestHeader("Authorization") String token,
            @RequestBody UpdateUserRequest newInfo) {
        return ResponseEntity.ok(userService.updateUserInfo(token, newInfo));
    }

}
