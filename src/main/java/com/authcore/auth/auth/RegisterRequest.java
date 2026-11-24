package com.authcore.auth.auth;

import com.authcore.auth.common.NormalizedEmailDeserializer;
import com.authcore.auth.common.ValidPassword;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
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
public class RegisterRequest {
    @NotBlank
    @Size(max = 100)
    private String firstName;

    @Size(max = 100)
    private String lastName;

    @NotBlank
    @Email
    @Size(max = 254)
    @JsonDeserialize(using = NormalizedEmailDeserializer.class)
    private String email;

    @NotBlank
    @ValidPassword
    private String password;

}
