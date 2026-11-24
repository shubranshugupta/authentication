package com.authcore.auth.security;

import java.util.Date;

import javax.crypto.SecretKey;

import org.springframework.stereotype.Service;

import com.authcore.auth.common.AuthConfigProperties;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

/** Creates and checks the access tokens. */
@Service
public class JwtService {
    public static final String INVALID_TOKEN = "The access token is invalid.";

    private final SecretKey signingKey;
    private final long expireTime;

    public JwtService(AuthConfigProperties authConfigProperties) {
        AuthConfigProperties.TokenConfigProperties token = authConfigProperties.getToken();
        this.signingKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(token.getSecretKey()));
        this.expireTime = token.getJwtExpiration();
    }

    public String generateToken(String email) {
        long now = System.currentTimeMillis();
        return Jwts.builder()
                .subject(email)
                .issuedAt(new Date(now))
                .expiration(new Date(now + expireTime))
                .signWith(signingKey, Jwts.SIG.HS256)
                .compact();
    }

    /**
     * Returns the email a valid token was issued to.
     *
     * @throws TokenExpireException  if the token was valid once
     * @throws InvalidTokenException if it was never valid: wrong signature, or not a JWT
     */
    public String extractEmail(String token) {
        Claims claims;
        try {
            claims = Jwts.parser()
                    .verifyWith(signingKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (ExpiredJwtException e) {
            throw new TokenExpireException("The access token has expired.", e);
        } catch (JwtException | IllegalArgumentException e) {
            throw new InvalidTokenException(INVALID_TOKEN, e);
        }
        // The parser accepts a token without an expiry; this server never issues one.
        if (claims.getSubject() == null || claims.getExpiration() == null)
            throw new InvalidTokenException(INVALID_TOKEN);
        return claims.getSubject();
    }
}
