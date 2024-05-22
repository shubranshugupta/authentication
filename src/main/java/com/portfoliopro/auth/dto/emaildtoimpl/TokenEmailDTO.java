package com.portfoliopro.auth.dto.emaildtoimpl;

import java.util.HashMap;
import java.util.Map;

import com.portfoliopro.auth.dto.EmailDTO;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class TokenEmailDTO implements EmailDTO {
    private String email;
    private String firstName;
    private String lastName;
    private String token;
    private String baseUrl;

    @Override
    public Map<String, String> getAllData() {
        HashMap<String, String> data = new HashMap<>();
        data.put("email", email);
        data.put("firstName", firstName);
        data.put("lastName", lastName);
        data.put("token", token);
        data.put("baseUrl", baseUrl);
        return data;
    }
}
