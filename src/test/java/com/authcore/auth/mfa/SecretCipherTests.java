package com.authcore.auth.mfa;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

import com.authcore.auth.common.AuthConfigProperties;

class SecretCipherTests {
    private static final byte[] SECRET = "12345678901234567890".getBytes();

    private final SecretCipher cipher = cipher("dGVzdC1vbmx5LXRvdHAta2V5LTMyLWJ5dGVzLWxvbmc=");

    @Test
    void aSecretComesBackAsItWas() {
        byte[] stored = cipher.encrypt(7, SECRET);

        assertThat(cipher.decrypt(7, stored)).isEqualTo(SECRET);
        // Version byte, 12-byte IV, the secret, and a 16-byte tag; the secret itself isn't in it.
        assertThat(stored).hasSize(1 + 12 + SECRET.length + 16);
        assertThat(new String(stored, java.nio.charset.StandardCharsets.ISO_8859_1)).doesNotContain(new String(SECRET));
    }

    @Test
    void theSameSecretIsStoredDifferentlyEachTime() {
        assertThat(cipher.encrypt(7, SECRET)).isNotEqualTo(cipher.encrypt(7, SECRET));
    }

    @Test
    void aSecretCopiedToAnotherUserDoesNotDecrypt() {
        byte[] stored = cipher.encrypt(7, SECRET);

        assertThatThrownBy(() -> cipher.decrypt(8, stored)).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void anotherKeyOrAChangedByteDoesNotDecrypt() {
        byte[] stored = cipher.encrypt(7, SECRET);
        SecretCipher other = cipher("b3RoZXItdG90cC1rZXktdGhhdC1pcy0zMi1ieXRlcyE=");

        assertThatThrownBy(() -> other.decrypt(7, stored)).isInstanceOf(IllegalStateException.class);
        stored[stored.length - 1] ^= 1;
        assertThatThrownBy(() -> cipher.decrypt(7, stored)).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void recoveryCodeHashesDependOnTheUserAndTheKey() {
        String hash = cipher.hash(7, "abcdefghij");

        assertThat(hash).hasSize(64).isEqualTo(cipher.hash(7, "abcdefghij"));
        assertThat(cipher.hash(8, "abcdefghij")).isNotEqualTo(hash);
        assertThat(cipher("b3RoZXItdG90cC1rZXktdGhhdC1pcy0zMi1ieXRlcyE=").hash(7, "abcdefghij")).isNotEqualTo(hash);
    }

    private static SecretCipher cipher(String key) {
        AuthConfigProperties properties = new AuthConfigProperties();
        properties.getTotp().setEncryptionKey(key);
        return new SecretCipher(properties);
    }
}
