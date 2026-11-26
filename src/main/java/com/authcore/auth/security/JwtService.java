package com.authcore.auth.security;

import java.time.Instant;
import java.util.Date;
import java.util.UUID;

import javax.crypto.SecretKey;

import org.springframework.stereotype.Service;

import com.authcore.auth.common.AuthConfigProperties;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

/** Creates and checks the access tokens. */
@Service
public class JwtService {
    public static final String INVALID_TOKEN = "The access token is invalid.";

    private static final String VERSION = "ver";

    private final AuthConfigProperties.TokenConfigProperties settings;
    private final SecretKey signingKey;
    private final JwtParser parser;

    public JwtService(AuthConfigProperties authConfigProperties) {
        this.settings = authConfigProperties.getToken();
        this.signingKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(settings.getSecretKey()));
        // Issuer and audience: a token that another service (or environment) signed with the
        // same key isn't accepted here.
        this.parser = Jwts.parser()
                .verifyWith(signingKey)
                .requireIssuer(settings.getIssuer())
                .requireAudience(settings.getAudience())
                .build();
    }

    public String generateToken(AccessToken token) {
        Instant now = Instant.now();
        return Jwts.builder()
                .id(UUID.randomUUID().toString())
                .issuer(settings.getIssuer())
                .audience().add(settings.getAudience()).and()
                // The id, not the email: an email can belong to another account later.
                .subject(token.userId().toString())
                .claim(VERSION, token.tokenVersion())
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusMillis(settings.getJwtExpiration())))
                .signWith(signingKey, Jwts.SIG.HS256)
                .compact();
    }

    /**
     * Checks the signature, the expiry and that nothing is missing. Whether the token was
     * revoked since is checked by JwtAuthFilter.
     *
     * @throws TokenExpireException  if the token was valid once
     * @throws InvalidTokenException if it was never valid: wrong signature, or not a JWT
     */
    public AccessToken parse(String token) {
        try {
            Claims claims = parser.parseSignedClaims(token).getPayload();
            Integer version = claims.get(VERSION, Integer.class);
            // The parser accepts a token without an expiry; this server never issues one.
            if (claims.getSubject() == null || claims.getExpiration() == null || version == null)
                throw new InvalidTokenException(INVALID_TOKEN);
            return new AccessToken(Integer.valueOf(claims.getSubject()), version);
        } catch (ExpiredJwtException e) {
            throw new TokenExpireException("The access token has expired.", e);
        } catch (JwtException | IllegalArgumentException e) { // includes a subject that isn't a number
            throw new InvalidTokenException(INVALID_TOKEN, e);
        }
    }
}
