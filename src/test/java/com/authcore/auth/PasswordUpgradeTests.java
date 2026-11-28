package com.authcore.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.authcore.auth.support.IntegrationTest;

import jakarta.servlet.http.Cookie;

/** F5: bcrypt hashes from before Argon2id still work, and are replaced at the next login. */
class PasswordUpgradeTests extends IntegrationTest {
    private static final String NEW_PASSWORD = "N3w-Str0ng-Passw0rd!";

    @Test
    void newPasswordsAreHashedWithArgon2id() throws Exception {
        String email = uniqueEmail();
        registerVerifiedUserAndLogin(email);

        assertThat(hash(email)).startsWith("{argon2}$argon2id$");
    }

    @Test
    void anOldBcryptHashLogsInAndIsReplacedWithoutEndingSessions() throws Exception {
        String email = uniqueEmail();
        registerVerifiedUserAndLogin(email);
        Cookie before = refreshCookie(email, PASSWORD);
        setOldBcryptHash(email, PASSWORD);
        int version = user(email).getTokenVersion();

        login(email, PASSWORD).andExpect(status().isOk());

        assertThat(hash(email)).startsWith("{argon2}$argon2id$");
        assertThat(user(email).getTokenVersion()).isEqualTo(version);
        refresh(before).andExpect(status().isOk());
        login(email, PASSWORD).andExpect(status().isOk());
    }

    @Test
    void aWrongPasswordUpgradesNothing() throws Exception {
        String email = uniqueEmail();
        registerVerifiedUserAndLogin(email);
        String old = setOldBcryptHash(email, PASSWORD);

        login(email, "Wrong-passw0rd!").andExpect(status().isUnauthorized());

        assertThat(hash(email)).isEqualTo(old);
    }

    @Test
    void anUnverifiedAccountIsNotUpgraded() throws Exception {
        String email = uniqueEmail();
        register(email, PASSWORD).andExpect(status().isOk());
        String old = setOldBcryptHash(email, PASSWORD);

        login(email, PASSWORD).andExpect(status().isForbidden());

        assertThat(hash(email)).isEqualTo(old);
    }

    @Test
    void anOldHashWorksForEverythingThatChecksThePassword() throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);
        setOldBcryptHash(email, PASSWORD);

        // Typing the password again (here for a password change) checks it like a login does.
        mvc.perform(as(accessToken, put("/api/v1/users/me/password")).contentType(MediaType.APPLICATION_JSON)
                .content("{\"currentPassword\": \"%s\", \"newPassword\": \"%s\"}".formatted(PASSWORD, NEW_PASSWORD)))
                .andExpect(status().isOk());

        assertThat(hash(email)).startsWith("{argon2}$argon2id$");
        login(email, NEW_PASSWORD).andExpect(status().isOk());
    }

    /** As the hashes were stored before: bcrypt, without a prefix. */
    private String setOldBcryptHash(String email, String password) {
        String old = new BCryptPasswordEncoder().encode(password);
        jdbc.update("update users set password = ? where email = ?", old, email);
        return old;
    }

    private String hash(String email) {
        return jdbc.queryForObject("select password from users where email = ?", String.class, email);
    }
}
