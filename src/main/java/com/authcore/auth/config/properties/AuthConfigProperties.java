package com.authcore.auth.config.properties;

import java.util.List;
import java.util.Set;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.Valid;
import jakarta.validation.constraints.AssertTrue;
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
    @Valid
    private CookieConfigProperties cookie = new CookieConfigProperties();

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
     * Attributes of the refresh-token cookie. Defaults suit a frontend on the same site
     * as the API (localhost:3000 calling localhost:8080 counts as the same site). A
     * frontend on a different domain needs same-site None, which browsers only accept
     * together with secure.
     */
    @Data
    @NoArgsConstructor
    public static class CookieConfigProperties {
        private static final Set<String> SAME_SITE_VALUES = Set.of("Strict", "Lax", "None");

        private boolean secure = true;
        private String sameSite = "Strict";

        @AssertTrue(message = "auth.cookie.same-site must be Strict, Lax or None")
        public boolean isSameSiteValid() {
            return SAME_SITE_VALUES.contains(sameSite);
        }

        @AssertTrue(message = "auth.cookie.same-site=None requires auth.cookie.secure=true (browsers reject it otherwise)")
        public boolean isSameSiteNoneSecure() {
            return !"None".equals(sameSite) || secure;
        }
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
