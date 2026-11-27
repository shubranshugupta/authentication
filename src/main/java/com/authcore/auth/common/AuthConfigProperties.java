package com.authcore.auth.common;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.StringUtils;
import org.springframework.validation.annotation.Validated;

import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.DecodingException;
import jakarta.validation.Valid;
import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Data
@Validated
@Configuration
@ConfigurationProperties("auth")
public class AuthConfigProperties {
    /**
     * Where the web app runs. Emails link to its pages, so it's validated at startup: an
     * unset FRONTEND_URL would otherwise only show up as broken links.
     */
    private String frontendUrl;

    @AssertTrue(message = "auth.frontend-url (FRONTEND_URL) must be a URL like https://app.example.com")
    public boolean isFrontendUrlValid() {
        try {
            URI url = new URI(String.valueOf(frontendUrl));
            return ("https".equals(url.getScheme()) || "http".equals(url.getScheme())) && url.getHost() != null
                    && url.getQuery() == null && url.getFragment() == null;
        } catch (URISyntaxException e) {
            return false;
        }
    }

    /** A page of the web app, e.g. "/verify-email". */
    public String frontendPage(String path) {
        return StringUtils.trimTrailingCharacter(frontendUrl, '/') + path;
    }

    /**
     * Emails that get the ADMIN role: at registration, and for existing users at
     * startup. This is how the first admins are created; they can make others admins.
     */
    private List<String> adminEmails = new ArrayList<>();
    @Valid
    private TokenConfigProperties token = new TokenConfigProperties();
    private CorsConfigProperties cors = new CorsConfigProperties();

    /** Whether this email is listed in auth.admin-emails (case-insensitive). */
    public boolean isAdminEmail(String email) {
        return email != null && adminEmails.stream()
                .anyMatch(admin -> admin.trim().toLowerCase(Locale.ROOT).equals(email.trim().toLowerCase(Locale.ROOT)));
    }

    @Valid
    private MailConfigProperties mail = new MailConfigProperties();
    @Valid
    private CookieConfigProperties cookie = new CookieConfigProperties();
    @Valid
    private TotpConfigProperties totp = new TotpConfigProperties();

    /** Two-factor authentication with an authenticator app (F5). */
    @Data
    @NoArgsConstructor
    public static class TotpConfigProperties {
        private static final int KEY_BYTES = 32;

        /** Encrypts the users' TOTP secrets. Changing it makes every one of them unusable. */
        @ToString.Exclude
        private String encryptionKey;

        /** The name authenticator apps show next to the codes. */
        @NotBlank
        private String issuer = "AuthCore";

        // On a boolean, like the JWT key: the startup error must not print the key.
        @AssertTrue(message = "auth.totp.encryption-key (TOTP_ENCRYPTION_KEY) must be a base64 key of exactly "
                + KEY_BYTES + " bytes")
        public boolean isEncryptionKeyValid() {
            try {
                return encryptionKey != null && Decoders.BASE64.decode(encryptionKey).length == KEY_BYTES;
            } catch (DecodingException e) {
                return false;
            }
        }
    }

    /**
     * Expirations are in milliseconds. Validated at startup: an unset JWT_SECRET_KEY is
     * bound as the literal text "${JWT_SECRET_KEY}" and would only fail at the first login.
     */
    @Data
    @NoArgsConstructor
    public static class TokenConfigProperties {
        private static final int MIN_SECRET_KEY_BYTES = 32;

        @ToString.Exclude
        private String secretKey;
        /** The "iss" and "aud" of every access token. Tokens with others are refused. */
        @NotBlank
        private String issuer;
        @NotBlank
        private String audience;
        @Positive
        private long jwtExpiration;
        /** How long a session lasts after it was last used. */
        @Positive
        private long refreshExpiration;
        /** How long a session lasts at most, however often it's used. */
        @Positive
        private long sessionExpiration;

        // A check on a boolean, not on the field: the startup error prints the rejected
        // value, and that must not be the key.
        @AssertTrue(message = "auth.token.secret-key (JWT_SECRET_KEY) must be a base64 key of at least "
                + MIN_SECRET_KEY_BYTES + " bytes")
        public boolean isSecretKeyValid() {
            try {
                return secretKey != null && Decoders.BASE64.decode(secretKey).length >= MIN_SECRET_KEY_BYTES;
            } catch (DecodingException e) {
                return false;
            }
        }
    }

    @Data
    @NoArgsConstructor
    public static class CorsConfigProperties {
        private List<String> allowedOrigins;
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
