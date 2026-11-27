package com.authcore.auth.auth;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * @param challenge from the login's first step
 * @param code      the 6 digits from the authenticator app, or a recovery code
 */
public record SecondFactorRequest(@NotBlank @Size(max = 1024) String challenge, @NotBlank @Size(max = 32) String code) {
    /** Leaves both out: logs must not contain them. */
    @Override
    public String toString() {
        return "SecondFactorRequest[]";
    }
}
