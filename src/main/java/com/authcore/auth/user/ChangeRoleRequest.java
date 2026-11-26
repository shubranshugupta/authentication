package com.authcore.auth.user;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

/** The new role, and the admin's own password. */
public record ChangeRoleRequest(@NotNull Role role, @NotBlank @Size(max = 256) String password) {

    @Override
    public String toString() {
        return "ChangeRoleRequest[role=" + role + "]";
    }
}
