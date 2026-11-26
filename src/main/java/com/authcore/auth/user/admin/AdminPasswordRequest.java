package com.authcore.auth.user.admin;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** The admin's own password, which every admin action that changes something asks for. */
public record AdminPasswordRequest(@NotBlank @Size(max = 256) String password) {

    @Override
    public String toString() {
        return "AdminPasswordRequest[]";
    }
}
