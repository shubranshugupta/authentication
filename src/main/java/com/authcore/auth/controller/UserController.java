package com.authcore.auth.controller;

import org.jspecify.annotations.Nullable;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.authcore.auth.dto.request.DeleteAccountRequest;
import com.authcore.auth.dto.request.UpdateUserRequest;
import com.authcore.auth.dto.response.MsgResponse;
import com.authcore.auth.dto.response.UserResponse;
import com.authcore.auth.security.UserPrincipal;
import com.authcore.auth.service.UserService;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/user")
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;

    @GetMapping("/get-info")
    public ResponseEntity<UserResponse> getUserInfo(@AuthenticationPrincipal UserPrincipal me) {
        return ResponseEntity.ok(userService.getProfile(me.id()));
    }

    @PutMapping("/update-info")
    public ResponseEntity<MsgResponse> updateUser(@AuthenticationPrincipal UserPrincipal me,
            @Valid @RequestBody UpdateUserRequest newInfo) {
        userService.updateProfile(me.id(), newInfo.getFirstName(), newInfo.getLastName());
        return message("User info updated successfully.");
    }

    @DeleteMapping("/delete")
    public ResponseEntity<MsgResponse> deleteUser(@AuthenticationPrincipal UserPrincipal me,
            @Valid @RequestBody(required = false) @Nullable DeleteAccountRequest request) {
        if (request == null) {
            userService.requestDeletion(me.id());
            return message("Delete account email sent.");
        }
        userService.confirmDeletion(me.id(), String.valueOf(request.getOtp()));
        return message("User deleted successfully.");
    }

    private static ResponseEntity<MsgResponse> message(String msg) {
        return ResponseEntity.ok(MsgResponse.builder().msg(msg).build());
    }
}
