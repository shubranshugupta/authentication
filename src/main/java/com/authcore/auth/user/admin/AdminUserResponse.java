package com.authcore.auth.user.admin;

import com.authcore.auth.user.Role;
import com.authcore.auth.user.User;

import java.util.Date;

/** A user as admins see it. Never includes the password hash or any token. */
public record AdminUserResponse(
        Integer id,
        String email,
        String firstName,
        String lastName,
        Role role,
        boolean emailVerified,
        boolean locked,
        Date createdAt,
        Date updatedAt) {

    public static AdminUserResponse from(User user) {
        return new AdminUserResponse(
                user.getId(),
                user.getEmail(),
                user.getFirstName(),
                user.getLastName(),
                user.getRole(),
                user.isEnabled(),
                user.isLocked(),
                user.getCreatedAt(),
                user.getUpdatedAt());
    }
}
