package com.authcore.auth.user.admin;

import java.time.Instant;

import com.authcore.auth.user.Role;
import com.authcore.auth.user.User;

/** A user as admins see it. Never includes the password hash or any token. */
public record AdminUserResponse(
        Integer id,
        String email,
        String firstName,
        String lastName,
        Role role,
        boolean emailVerified,
        boolean locked,
        boolean twoFactorEnabled,
        Instant createdAt,
        Instant updatedAt) {

    public static AdminUserResponse from(User user, boolean twoFactorEnabled) {
        return new AdminUserResponse(
                user.getId(),
                user.getEmail(),
                user.getFirstName(),
                user.getLastName(),
                user.getRole(),
                user.isEnabled(),
                user.isLocked(),
                twoFactorEnabled,
                user.getCreatedAt(),
                user.getUpdatedAt());
    }
}
