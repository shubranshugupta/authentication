package com.authcore.auth.auth;

import com.fasterxml.jackson.annotation.JsonInclude;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * The answer to a login or a refresh: an access token. For a user with two-factor
 * authentication, a login's first step answers {@code secondFactorRequired} and a
 * {@code challenge} instead, for {@code POST /api/v1/auth/login/2fa}.
 */
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AuthResponse {
    private String accessToken;
    private Boolean secondFactorRequired;
    private String challenge;

    public AuthResponse(String accessToken) {
        this.accessToken = accessToken;
    }

    static AuthResponse secondFactorRequired(String challenge) {
        return new AuthResponse(null, true, challenge);
    }
}
