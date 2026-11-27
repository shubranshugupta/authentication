package com.authcore.auth.auth;

import com.authcore.auth.common.ValidPassword;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * @param token    from the link sent to the old address
 * @param password the new password: whoever changed the email knew the old one
 */
public record UndoEmailChangeRequest(
        @NotBlank @Size(max = 64) String token,
        @NotBlank @ValidPassword String password) {

    /** Leaves both out: logs must not contain them. */
    @Override
    public String toString() {
        return "UndoEmailChangeRequest[]";
    }
}
