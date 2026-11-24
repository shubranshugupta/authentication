package com.authcore.auth.config.properties;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Validated
@Configuration
@ConfigurationProperties("auth")
public class AuthConfigProperties {
    private String baseUrl;
    private TokenConfigProperties token = new TokenConfigProperties();
    private CorsConfigProperties cors = new CorsConfigProperties();
    @Valid
    private MailConfigProperties mail = new MailConfigProperties();

    @Data
    @NoArgsConstructor
    public static class TokenConfigProperties {
        private String secretKey;
        private long jwtExpiration;
        private long refreshExpiration;
        private long tokenExpiration;
    }

    @Data
    @NoArgsConstructor
    public static class CorsConfigProperties {
        private List<String> allowedOrigin;
        private List<String> allowedMethods;
        private List<String> allowedHeaders;
    }

    /**
     * The sender of every email. Kept separate from the SMTP login, because most
     * providers (Amazon SES included) don't use an email address as the username.
     * Validated at startup, so an unset MAIL_FROM stops the app instead of failing
     * on the first email.
     */
    @Data
    @NoArgsConstructor
    public static class MailConfigProperties {
        @NotBlank
        @Email
        private String from;

        @NotBlank
        private String fromName;
    }
}
