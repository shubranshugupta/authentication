package com.authcore.auth.user;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class DeleteAccountRequest {
    @NotNull
    @Pattern(regexp = "\\d{8}", message = "must be the 8 digits from the email")
    private String otp;

    @NotBlank
    private String password;
}
