package com.authcore.auth.dto.request;

import com.authcore.auth.validation.ValidPassword;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class ResetPasswordRequest {
    // Long, not long: a missing OTP is rejected instead of silently becoming 0.
    @NotNull
    private Long otp;

    @NotBlank
    @ValidPassword
    private String password;
}
