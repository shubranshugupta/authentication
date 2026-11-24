package com.authcore.auth.auth;

import com.authcore.auth.common.NormalizedEmailDeserializer;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import tools.jackson.databind.annotation.JsonDeserialize;

/** Asks for an email to this account: a new verification link, or a password reset code. */
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AccountEmailRequest {
    @NotBlank
    @Email
    @Size(max = 254)
    @JsonDeserialize(using = NormalizedEmailDeserializer.class)
    private String email;
}
