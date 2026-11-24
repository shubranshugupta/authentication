package com.authcore.auth.auth;

import com.authcore.auth.common.NormalizedEmailDeserializer;
import com.authcore.auth.common.ValidPassword;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import tools.jackson.databind.annotation.JsonDeserialize;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class ResetPasswordRequest {
    @NotBlank
    @Email
    @Size(max = 254)
    @JsonDeserialize(using = NormalizedEmailDeserializer.class)
    private String email;

    @NotNull
    @Pattern(regexp = "\\d{8}", message = "must be the 8 digits from the email")
    private String otp;

    @NotBlank
    @ValidPassword
    private String password;
}
