package com.authcore.auth.mfa;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.security.GeneralSecurityException;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Optional;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.stereotype.Component;

import com.authcore.auth.common.AuthConfigProperties;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

/**
 * The token that carries a login from its first step (the password) to its second (the code
 * from the app). It says whose password was right and when, and lasts 5 minutes.
 *
 * <p>Signed with a key of its own, derived from the JWT key: it can never pass for an access
 * token, nor one for it. It names the user's token version, so a password change or reset,
 * a lock or "log out everywhere" in the meantime makes it useless. It can be used more than
 * once within the 5 minutes, but each time with a new code: a code works once.
 */
@Component
public class LoginChallenges {
    public static final Duration VALID_FOR = Duration.ofMinutes(5);

    private static final String AUDIENCE = "login-challenge";
    private static final String VERSION = "ver";

    private final SecretKey key;
    private final JwtParser parser;
    private final String issuer;

    LoginChallenges(AuthConfigProperties properties) {
        byte[] secret = Decoders.BASE64.decode(properties.getToken().getSecretKey());
        this.key = Keys.hmacShaKeyFor(hmac(secret, "login-challenges"));
        this.issuer = properties.getToken().getIssuer();
        this.parser = Jwts.parser().verifyWith(key).requireIssuer(issuer).requireAudience(AUDIENCE).build();
    }

    /** The user's password was just checked. */
    public String issue(Integer userId, int tokenVersion) {
        Instant now = Instant.now();
        return Jwts.builder()
                .issuer(issuer)
                .audience().add(AUDIENCE).and()
                .subject(userId.toString())
                .claim(VERSION, tokenVersion)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plus(VALID_FOR)))
                .signWith(key, Jwts.SIG.HS256)
                .compact();
    }

    /** @return empty if it's not one of ours, or has expired */
    public Optional<Challenge> parse(String token) {
        try {
            Claims claims = parser.parseSignedClaims(token).getPayload();
            Integer version = claims.get(VERSION, Integer.class);
            if (claims.getSubject() == null || claims.getExpiration() == null || version == null)
                return Optional.empty();
            return Optional.of(new Challenge(Integer.valueOf(claims.getSubject()), version));
        } catch (JwtException | IllegalArgumentException e) {
            return Optional.empty();
        }
    }

    /** @param tokenVersion the user's version when the password was checked */
    public record Challenge(Integer userId, int tokenVersion) {
    }

    private static byte[] hmac(byte[] key, String text) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(text.getBytes(UTF_8));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e); // every Java has HmacSHA256
        }
    }
}
