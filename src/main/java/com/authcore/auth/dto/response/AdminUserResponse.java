package com.authcore.auth.dto.response;

import java.util.Date;

import com.authcore.auth.entities.Role;
import com.authcore.auth.entities.User;

/** A user as admins see it. Never includes the password hash or any token. */
public record AdminUserResponse(
        Integer id,
        String email,
        String firstName,
        String lastName,
        Role role,
        boolean emailVerified,
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
                user.getCreatedAt(),
                user.getUpdatedAt());
    }
}
