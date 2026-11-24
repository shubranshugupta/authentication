package com.authcore.auth.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class LoginRequest {
    // No password policy here: existing passwords may predate it.
    @NotBlank
    @Size(max = 254)
    String email;

    @NotBlank
    @Size(max = 256)
    String password;

}
