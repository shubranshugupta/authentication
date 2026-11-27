package com.authcore.auth.user.account;

import com.authcore.auth.common.NormalizedEmailDeserializer;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import tools.jackson.databind.annotation.JsonDeserialize;

/** @param currentPassword only checked, like for a password change */
public record ChangeEmailRequest(
        @NotBlank @Size(max = 256) String currentPassword,
        @NotBlank @Email @Size(max = 254) @JsonDeserialize(using = NormalizedEmailDeserializer.class) String newEmail) {

    /** Leaves the password out: logs must not contain it. */
    @Override
    public String toString() {
        return "ChangeEmailRequest[]";
    }
}
