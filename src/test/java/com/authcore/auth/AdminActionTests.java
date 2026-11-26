package com.authcore.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import java.util.concurrent.ThreadLocalRandom;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import com.authcore.auth.support.IntegrationTest;
import com.authcore.auth.user.AdminBootstrap;
import com.authcore.auth.user.Role;

/** What admins can do with users: lock, unlock, log out, and change the role. Each needs the admin's password. */
class AdminActionTests extends IntegrationTest {
    private static final String LIST = "/api/v1/admin/users";
    private static final String USERS = LIST + "/";
    private static final String NEW_PASSWORD = "N3w-Str0ng-Passw0rd!";
    /** Not the users' {@link #PASSWORD}, so a test can tell whose password was checked. */
    private static final String ADMIN_PASSWORD = "Adm1n-Str0ng-Passw0rd!";
    private static final String WRONG = "Wrong-passw0rd!";

    @Autowired
    private AdminBootstrap adminBootstrap;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private String adminEmail;
    private String admin;
    private String email;
    private String accessToken;

    @BeforeEach
    void createAnAdminAndAUser() throws Exception {
        adminEmail = uniqueEmail();
        admin = registerVerifiedUserAndLogin(adminEmail);
        adminBootstrap.promote(List.of(adminEmail));
        // Directly in the database: a password reset would end the admin's session.
        jdbc.update("update users set password = ? where email = ?", passwordEncoder.encode(ADMIN_PASSWORD), adminEmail);
        email = uniqueEmail();
        accessToken = registerVerifiedUserAndLogin(email);
    }

    // ---- lock ----------------------------------------------------------------------

    @Test
    void lockingLogsTheUserOutEverywhereAndKeepsThemOut() throws Exception {
        ResultActions phone = login(email, PASSWORD);

        lock(email)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value(email))
                .andExpect(jsonPath("$.locked").value(true))
                .andExpect(jsonPath("$.emailVerified").value(true))
                .andExpect(jsonPath("$.password").doesNotExist());

        getProfile(accessToken).andExpect(status().isUnauthorized());
        getProfile(accessToken(phone)).andExpect(status().isUnauthorized());
        refresh(refreshCookie(phone)).andExpect(status().isUnauthorized());
        login(email, PASSWORD)
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("ACCOUNT_LOCKED"))
                .andExpect(jsonPath("$.detail").value("An administrator locked this account."));
    }

    /** H2: like an unverified account, only the owner can tell. */
    @Test
    void withoutThePasswordALockedAccountLooksLikeAnUnknownOne() throws Exception {
        lock(email);

        assertThat(login(email, "Wrong-passw0rd!").andExpect(status().isUnauthorized()).andReturn().getResponse().getContentAsString())
                .isEqualTo(login(uniqueEmail(), "Wrong-passw0rd!").andExpect(status().isUnauthorized()).andReturn().getResponse().getContentAsString());
        assertThat(requestPasswordReset(email).andExpect(status().isOk()).andReturn().getResponse().getContentAsString())
                .isEqualTo(requestPasswordReset(uniqueEmail()).andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
    }

    @Test
    void aLockedUserCannotResetThePassword() throws Exception {
        requestPasswordReset(email).andExpect(status().isOk());
        String otp = passwordResetOtp(email);
        lock(email);

        confirmPasswordReset(email, otp, NEW_PASSWORD).andExpect(status().isBadRequest()).andExpect(jsonPath("$.code").value("INVALID_CODE"));
        requestPasswordReset(email).andExpect(status().isOk());

        Thread.sleep(300); // nothing is sent, so there is nothing to wait for
        assertThat(sentEmails(email, "Password Reset")).hasSize(1);
        unlock(email);
        login(email, PASSWORD).andExpect(status().isOk());
    }

    @Test
    void unlockingLetsTheUserLogInAgainButNotWithOldTokens() throws Exception {
        lock(email);

        unlock(email).andExpect(status().isOk()).andExpect(jsonPath("$.locked").value(false));

        getProfile(accessToken).andExpect(status().isUnauthorized());
        getProfile(accessToken(email, PASSWORD)).andExpect(status().isOk());
    }

    @Test
    void lockingAndUnlockingTwiceIsHarmless() throws Exception {
        lock(email).andExpect(status().isOk());
        lock(email).andExpect(status().isOk()).andExpect(jsonPath("$.locked").value(true));
        unlock(email).andExpect(status().isOk());
        unlock(email).andExpect(status().isOk()).andExpect(jsonPath("$.locked").value(false));
    }

    /** Also if it was locked in the database by hand. */
    @Test
    void accessTokensOfALockedUserAreRefused() throws Exception {
        jdbc.update("update users set locked_at = utc_timestamp(6) where id = ?", user(email).getId());

        getProfile(accessToken).andExpect(status().isUnauthorized());
    }

    @Test
    void aLockedAdminIsNoAdminAnyMore() throws Exception {
        adminBootstrap.promote(List.of(email));
        perform(accessToken, get(LIST)).andExpect(status().isOk());

        lock(email).andExpect(status().isOk());

        perform(accessToken, get(LIST)).andExpect(status().isUnauthorized());
    }

    // ---- sessions ------------------------------------------------------------------

    @Test
    void adminsCanLogAUserOutEverywhere() throws Exception {
        ResultActions phone = login(email, PASSWORD);

        perform(admin, withPassword(post(USERS + user(email).getId() + "/logout"), ADMIN_PASSWORD)).andExpect(status().isOk());

        getProfile(accessToken).andExpect(status().isUnauthorized());
        refresh(refreshCookie(phone)).andExpect(status().isUnauthorized());
        login(email, PASSWORD).andExpect(status().isOk());
        getProfile(admin).andExpect(status().isOk());
    }

    // ---- roles ---------------------------------------------------------------------

    @Test
    void promotingTakesEffectAtOnceAndSoDoesDemoting() throws Exception {
        perform(accessToken, get(LIST)).andExpect(status().isForbidden());

        changeRole(email, "ADMIN").andExpect(status().isOk()).andExpect(jsonPath("$.role").value("ADMIN"));
        perform(accessToken, get(LIST)).andExpect(status().isOk());

        changeRole(email, "USER").andExpect(status().isOk()).andExpect(jsonPath("$.role").value("USER"));
        perform(accessToken, get(LIST)).andExpect(status().isForbidden());
    }

    /** The next start would promote them again. */
    @Test
    void adminsFromTheSettingsCannotBeDemoted() throws Exception {
        String listed = "second-admin@authcore.test"; // auth.admin-emails in application-test.yml
        register(listed, PASSWORD).andExpect(status().isOk());

        changeRole(listed, "USER")
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("ADMIN_ACTION_REFUSED"));

        assertThat(user(listed).getRole()).isEqualTo(Role.ADMIN);
        changeRole(listed, "ADMIN").andExpect(status().isOk());
    }

    @Test
    void theRoleMustBeOneThatExists() throws Exception {
        changeRole(email, "GOD").andExpect(status().isBadRequest()).andExpect(jsonPath("$.code").value("MALFORMED_BODY"));
        perform(admin, withPassword(put(USERS + user(email).getId() + "/role"), ADMIN_PASSWORD))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.errors.role").exists());
        assertThat(user(email).getRole()).isEqualTo(Role.USER);
    }

    // ---- who can do it -------------------------------------------------------------

    @Test
    void adminsCannotLockOrDemoteThemselves() throws Exception {
        lock(adminEmail).andExpect(status().isConflict()).andExpect(jsonPath("$.code").value("ADMIN_ACTION_REFUSED"));
        changeRole(adminEmail, "USER").andExpect(status().isConflict()).andExpect(jsonPath("$.code").value("ADMIN_ACTION_REFUSED"));

        perform(admin, get(LIST)).andExpect(status().isOk());
    }

    @Test
    void onlyAdminsCan() throws Exception {
        String victim = uniqueEmail();
        registerVerifiedUserAndLogin(victim);

        // With their own, right, password.
        for (MockHttpServletRequestBuilder request : actions(victim, PASSWORD))
            perform(accessToken, request).andExpect(status().isForbidden()).andExpect(jsonPath("$.code").value("ACCESS_DENIED"));
        for (MockHttpServletRequestBuilder request : actions(victim, ADMIN_PASSWORD))
            mvc.perform(request).andExpect(status().isUnauthorized());

        assertThat(user(victim).isLocked()).isFalse();
        assertThat(user(victim).getRole()).isEqualTo(Role.USER);
        login(victim, PASSWORD).andExpect(status().isOk());
    }

    @Test
    void unknownUsersAre404() throws Exception {
        for (MockHttpServletRequestBuilder request : actions(999999999, ADMIN_PASSWORD))
            perform(admin, request).andExpect(status().isNotFound()).andExpect(jsonPath("$.code").value("USER_NOT_FOUND"));
    }

    // ---- the admin's password ------------------------------------------------------

    /** A stolen access token isn't enough. */
    @Test
    void everyActionNeedsThePassword() throws Exception {
        for (MockHttpServletRequestBuilder request : actions(email, null))
            perform(admin, request).andExpect(status().isBadRequest()).andExpect(jsonPath("$.errors.password").exists());
        for (MockHttpServletRequestBuilder request : actions(email, ""))
            perform(admin, request).andExpect(status().isBadRequest()).andExpect(jsonPath("$.errors.password").exists());
        perform(admin, post(USERS + user(email).getId() + "/lock")).andExpect(status().isBadRequest());

        nothingHappenedTo(email);
    }

    @Test
    void aWrongPasswordChangesNothing() throws Exception {
        for (MockHttpServletRequestBuilder request : actions(email, WRONG))
            perform(admin, request)
                    .andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.code").value("WRONG_PASSWORD"))
                    .andExpect(jsonPath("$.detail").value("The password is wrong."));

        nothingHappenedTo(email);
        getProfile(admin).andExpect(status().isOk()); // a wrong password doesn't log the admin out
    }

    @Test
    void itMustBeTheAdminsOwnPassword() throws Exception {
        for (MockHttpServletRequestBuilder request : actions(email, PASSWORD)) // the user's
            perform(admin, request).andExpect(status().isForbidden()).andExpect(jsonPath("$.code").value("WRONG_PASSWORD"));

        nothingHappenedTo(email);
    }

    /** Like at login (H9), and they count there too: a stolen token can't guess the password. */
    @Test
    void wrongPasswordsAreLimitedLikeAtLogin() throws Exception {
        String ip = randomIp();
        String lock = USERS + user(email).getId() + "/lock";
        for (int i = 0; i < 5; i++)
            perform(admin, withPassword(post(lock), WRONG).with(from(ip))).andExpect(status().isForbidden());

        perform(admin, withPassword(post(lock), ADMIN_PASSWORD).with(from(ip)))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.code").value("TOO_MANY_REQUESTS"))
                .andExpect(header().exists(HttpHeaders.RETRY_AFTER));
        mvc.perform(post("/api/v1/auth/login").with(from(ip)).contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\": \"%s\", \"password\": \"%s\"}".formatted(adminEmail, ADMIN_PASSWORD)))
                .andExpect(status().isTooManyRequests());
        nothingHappenedTo(email);

        // Only from that address.
        perform(admin, withPassword(post(lock), ADMIN_PASSWORD).with(from(randomIp()))).andExpect(status().isOk());
    }

    @Test
    void theRightPasswordClearsTheWrongOnes() throws Exception {
        String ip = randomIp();
        String unlock = USERS + user(email).getId() + "/unlock";
        for (int round = 0; round < 3; round++) {
            for (int i = 0; i < 4; i++)
                perform(admin, withPassword(post(unlock), WRONG).with(from(ip))).andExpect(status().isForbidden());
            perform(admin, withPassword(post(unlock), ADMIN_PASSWORD).with(from(ip))).andExpect(status().isOk());
        }
    }

    // ---- helpers -------------------------------------------------------------------

    private void nothingHappenedTo(String email) throws Exception {
        assertThat(user(email).isLocked()).isFalse();
        assertThat(user(email).getRole()).isEqualTo(Role.USER);
        getProfile(accessToken).andExpect(status().isOk());
    }

    /** Every action that changes something, with this password (none if null). */
    private List<MockHttpServletRequestBuilder> actions(String email, String password) {
        return actions(user(email).getId(), password);
    }

    private static List<MockHttpServletRequestBuilder> actions(int id, String password) {
        String withPassword = password == null ? "" : ", \"password\": \"" + password + "\"";
        return List.of(
                withPassword(post(USERS + id + "/lock"), password),
                withPassword(post(USERS + id + "/unlock"), password),
                withPassword(post(USERS + id + "/logout"), password),
                put(USERS + id + "/role").contentType(MediaType.APPLICATION_JSON).content("{\"role\": \"ADMIN\"" + withPassword + "}"));
    }

    private static MockHttpServletRequestBuilder withPassword(MockHttpServletRequestBuilder request, String password) {
        return request.contentType(MediaType.APPLICATION_JSON)
                .content(password == null ? "{}" : "{\"password\": \"" + password + "\"}");
    }

    private ResultActions lock(String email) throws Exception {
        return perform(admin, withPassword(post(USERS + user(email).getId() + "/lock"), ADMIN_PASSWORD));
    }

    private ResultActions unlock(String email) throws Exception {
        return perform(admin, withPassword(post(USERS + user(email).getId() + "/unlock"), ADMIN_PASSWORD));
    }

    private ResultActions changeRole(String email, String role) throws Exception {
        return perform(admin, put(USERS + user(email).getId() + "/role").contentType(MediaType.APPLICATION_JSON)
                .content("{\"role\": \"" + role + "\", \"password\": \"" + ADMIN_PASSWORD + "\"}"));
    }

    private static String randomIp() {
        ThreadLocalRandom random = ThreadLocalRandom.current();
        return "100." + random.nextInt(256) + "." + random.nextInt(256) + "." + random.nextInt(256);
    }

    private ResultActions perform(String accessToken, MockHttpServletRequestBuilder request) throws Exception {
        return mvc.perform(as(accessToken, request));
    }
}
