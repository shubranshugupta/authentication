package com.authcore.auth.auth;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** @param code from the redirect after signing in with Google ({@code #code=...}) */
public record SocialLoginRequest(@NotBlank @Size(max = 64) String code) {
    /** Leaves the code out: logs must not contain it. */
    @Override
    public String toString() {
        return "SocialLoginRequest[]";
    }
}
