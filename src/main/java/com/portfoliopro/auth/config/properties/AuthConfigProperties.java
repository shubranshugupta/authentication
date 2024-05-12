package com.portfoliopro.auth.config.properties;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Configuration
@ConfigurationProperties("auth")
public class AuthConfigProperties {
    private TokenConfigProperties token = new TokenConfigProperties();
    private CorsConfigProperties cors = new CorsConfigProperties();

    @Data
    @NoArgsConstructor
    public static class TokenConfigProperties {
        private String secretKey;
        private long expiration;
        private long refreshExpiration;
        private long verifyExpiration;
        private long otpExpiration;
    }

    @Data
    @NoArgsConstructor
    public static class CorsConfigProperties {
        private List<String> allowedOrigin;
        private List<String> allowedMethods;
        private List<String> allowedHeaders;
    }
}