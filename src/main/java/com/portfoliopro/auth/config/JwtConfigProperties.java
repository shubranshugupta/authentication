package com.portfoliopro.auth.config;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Configuration
@ConfigurationProperties("jwt")
public class JwtConfigProperties {
    private JwtTokenConfigProperties token = new JwtTokenConfigProperties();
    private JwtCorsConfigProperties cors = new JwtCorsConfigProperties();

    @Data
    @NoArgsConstructor
    public static class JwtTokenConfigProperties {
        private String secretKey;
        private long expiration;
    }

    @Data
    @NoArgsConstructor
    public static class JwtCorsConfigProperties {
        private List<String> allowedOrigin;
        private List<String> allowedMethods;
        private List<String> allowedHeaders;
    }
}