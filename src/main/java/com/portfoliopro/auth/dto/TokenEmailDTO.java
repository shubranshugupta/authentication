package com.portfoliopro.auth.dto;

import java.io.Serializable;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@AllArgsConstructor
public class TokenEmailDTO implements Serializable {
    String email;
    String firstName;
    String lastName;
    String token;
}
