package com.authcore.auth.token;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.security.GeneralSecurityException;
import java.util.HexFormat;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.jspecify.annotations.Nullable;
import org.springframework.stereotype.Component;

import com.authcore.auth.common.AuthConfigProperties;

import io.jsonwebtoken.io.Decoders;

/**
 * Hashes codes and link tokens for the database (C1). With a secret key (HMAC): a code has
 * so few digits that a plain hash of it could be reversed by trying them all.
 */
@Component
class TokenHasher {
    private static final String ALGORITHM = "HmacSHA256";

    private final SecretKeySpec key;

    TokenHasher(AuthConfigProperties properties) {
        // A key of its own, derived from the JWT key, so neither can stand in for the other.
        byte[] secret = Decoders.BASE64.decode(properties.getToken().getSecretKey());
        this.key = new SecretKeySpec(hmac(new SecretKeySpec(secret, ALGORITHM), "one-time-tokens"), ALGORITHM);
    }

    /**
     * @param userId part of the hash of a code, so two users with the same code have
     *               different hashes; null for a link, which has to be found without its user
     */
    String hash(TokenPurpose purpose, @Nullable Integer userId, String token) {
        return HexFormat.of().formatHex(hmac(key, purpose + ":" + (userId == null ? "" : userId) + ":" + token));
    }

    private static byte[] hmac(SecretKeySpec key, String text) {
        try {
            Mac mac = Mac.getInstance(ALGORITHM);
            mac.init(key);
            return mac.doFinal(text.getBytes(UTF_8));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e); // every Java has HmacSHA256
        }
    }
}
