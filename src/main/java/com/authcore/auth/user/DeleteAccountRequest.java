package com.authcore.auth.user;

import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class DeleteAccountRequest {
    // Long, not long: a missing OTP is rejected instead of silently becoming 0.
    @NotNull
    private Long otp;
}
