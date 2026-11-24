package com.authcore.auth.auth;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class ConfirmEmailRequest {
    /** From the verification link; it also says whose email it is. */
    @NotBlank
    @Size(max = 200)
    @ToString.Exclude
    private String token;
}
