package com.authcore.auth.mfa;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.HexFormat;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.stereotype.Component;

import com.authcore.auth.common.AuthConfigProperties;

import io.jsonwebtoken.io.Decoders;

/**
 * Encrypts TOTP secrets for the database, and hashes recovery codes, with keys derived from
 * TOTP_ENCRYPTION_KEY. A copy of the database alone can neither make codes nor test guesses
 * at recovery codes.
 *
 * <p>AES-256-GCM, with the user's id as associated data: a secret copied to another user's
 * row doesn't decrypt. The stored value starts with a version byte, so the format or the key
 * can change later.
 */
@Component
class SecretCipher {
    private static final byte VERSION = 1;
    private static final int IV_BYTES = 12;
    private static final int TAG_BITS = 128;
    private static final SecureRandom RANDOM = new SecureRandom();

    private final SecretKeySpec encryptionKey;
    private final SecretKeySpec hashKey;

    SecretCipher(AuthConfigProperties properties) {
        byte[] master = Decoders.BASE64.decode(properties.getTotp().getEncryptionKey());
        SecretKeySpec masterKey = new SecretKeySpec(master, "HmacSHA256");
        // One key for each use, so neither can stand in for the other.
        this.encryptionKey = new SecretKeySpec(hmac(masterKey, "totp-secrets"), "AES");
        this.hashKey = new SecretKeySpec(hmac(masterKey, "recovery-codes"), "HmacSHA256");
    }

    byte[] encrypt(Integer userId, byte[] secret) {
        byte[] iv = new byte[IV_BYTES];
        RANDOM.nextBytes(iv);
        byte[] encrypted = cipher(Cipher.ENCRYPT_MODE, userId, iv).apply(secret);
        return ByteBuffer.allocate(1 + IV_BYTES + encrypted.length).put(VERSION).put(iv).put(encrypted).array();
    }

    /** @throws IllegalStateException if it wasn't encrypted for this user with this key */
    byte[] decrypt(Integer userId, byte[] stored) {
        if (stored.length <= 1 + IV_BYTES || stored[0] != VERSION)
            throw new IllegalStateException("Unknown TOTP secret format");
        ByteBuffer buffer = ByteBuffer.wrap(stored, 1, stored.length - 1);
        byte[] iv = new byte[IV_BYTES];
        buffer.get(iv);
        byte[] encrypted = new byte[buffer.remaining()];
        buffer.get(encrypted);
        return cipher(Cipher.DECRYPT_MODE, userId, iv).apply(encrypted);
    }

    /** With the user's id: two users with the same code have different hashes. */
    String hash(Integer userId, String recoveryCode) {
        return HexFormat.of().formatHex(hmac(hashKey, userId + ":" + recoveryCode));
    }

    private interface Operation {
        byte[] apply(byte[] input);
    }

    private Operation cipher(int mode, Integer userId, byte[] iv) {
        return input -> {
            try {
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(mode, encryptionKey, new GCMParameterSpec(TAG_BITS, iv));
                cipher.updateAAD(("user:" + userId).getBytes(UTF_8));
                return cipher.doFinal(input);
            } catch (GeneralSecurityException e) {
                // A different key (TOTP_ENCRYPTION_KEY changed) or a tampered row.
                throw new IllegalStateException("The TOTP secret can't be decrypted", e);
            }
        };
    }

    private static byte[] hmac(SecretKeySpec key, String text) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(key);
            return mac.doFinal(text.getBytes(UTF_8));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e); // every Java has HmacSHA256
        }
    }
}
