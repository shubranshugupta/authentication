package com.authcore.auth.user.account;

import com.authcore.auth.common.ValidPassword;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * @param currentPassword only checked, so it isn't held to today's rules: it may be one
 *                        that was set before them
 */
public record ChangePasswordRequest(
        @NotBlank @Size(max = 256) String currentPassword,
        @NotBlank @ValidPassword String newPassword) {

    /** Leaves both passwords out: logs must not contain them. */
    @Override
    public String toString() {
        return "ChangePasswordRequest[]";
    }
}
