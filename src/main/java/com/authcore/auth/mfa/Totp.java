package com.authcore.auth.mfa;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.time.Instant;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Time-based one-time passwords (RFC 6238) as authenticator apps make them: HMAC-SHA1,
 * 6 digits, a new code every 30 seconds. Every app supports these settings; some ignore
 * any others.
 */
public final class Totp {
    public static final Duration STEP = Duration.ofSeconds(30);
    public static final int DIGITS = 6;
    /** 160 bits, the size of an HMAC-SHA1 key (RFC 4226 recommends it). */
    static final int SECRET_BYTES = 20;

    private static final int MODULUS = 1_000_000;
    private static final String BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    private Totp() {
    }

    /** The time step a moment falls in. */
    public static long step(Instant moment) {
        return Math.floorDiv(moment.getEpochSecond(), STEP.toSeconds());
    }

    /** The code for one time step (RFC 4226, section 5.3). */
    public static String code(byte[] secret, long step) {
        try {
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(secret, "HmacSHA1"));
            byte[] hash = mac.doFinal(ByteBuffer.allocate(Long.BYTES).putLong(step).array());
            int offset = hash[hash.length - 1] & 0x0f;
            int binary = ((hash[offset] & 0x7f) << 24) | ((hash[offset + 1] & 0xff) << 16)
                    | ((hash[offset + 2] & 0xff) << 8) | (hash[offset + 3] & 0xff);
            return String.format("%0" + DIGITS + "d", binary % MODULUS);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e); // every Java has HmacSHA1
        }
    }

    /** The secret as apps take it: base32 (RFC 4648) without padding. */
    public static String base32(byte[] bytes) {
        StringBuilder text = new StringBuilder();
        int buffer = 0;
        int bits = 0;
        for (byte b : bytes) {
            buffer = (buffer << 8) | (b & 0xff);
            bits += 8;
            while (bits >= 5) {
                text.append(BASE32.charAt((buffer >> (bits - 5)) & 0x1f));
                bits -= 5;
            }
        }
        if (bits > 0)
            text.append(BASE32.charAt((buffer << (5 - bits)) & 0x1f));
        return text.toString();
    }

    /** The reverse of {@link #base32}, for tests and scripts that act as the app. */
    public static byte[] fromBase32(String text) {
        ByteBuffer bytes = ByteBuffer.allocate(text.length() * 5 / 8);
        int buffer = 0;
        int bits = 0;
        for (char c : text.toUpperCase().toCharArray()) {
            int value = BASE32.indexOf(c);
            if (value < 0)
                throw new IllegalArgumentException("Not base32: " + c);
            buffer = (buffer << 5) | value;
            bits += 5;
            if (bits >= 8) {
                bytes.put((byte) (buffer >> (bits - 8)));
                bits -= 8;
            }
        }
        return bytes.array();
    }
}
