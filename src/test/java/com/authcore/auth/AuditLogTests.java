package com.authcore.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import java.util.concurrent.ThreadLocalRandom;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import com.authcore.auth.support.IntegrationTest;
import com.authcore.auth.user.admin.AdminBootstrap;

import io.micrometer.core.instrument.MeterRegistry;
import jakarta.servlet.http.Cookie;

/** F2: one audit line per security event, with ids and addresses, never emails or secrets. */
@ExtendWith(OutputCaptureExtension.class)
class AuditLogTests extends IntegrationTest {
    private static final String WRONG = "Wrong-passw0rd!";
    private static final String NEW_PASSWORD = "N3w-Str0ng-Passw0rd!";

    @Autowired
    private AdminBootstrap adminBootstrap;

    @Autowired
    private MeterRegistry meters;

    // ---- logins --------------------------------------------------------------------

    @Test
    void aLoginIsRecordedWithItsSessionAddressAndTraceId(CapturedOutput output) throws Exception {
        String email = uniqueEmail();
        registerVerifiedUserAndLogin(email);
        String ip = randomIp();

        mvc.perform(loginRequest(email, PASSWORD).with(from(ip))).andExpect(status().isOk());

        String line = auditLine(output, "LOGIN_SUCCEEDED", user(email).getId(), "ip=" + ip);
        assertThat(line).containsPattern("sessionId=\\d+").containsPattern("[0-9a-f]{32}");
    }

    @Test
    void failedLoginsSayWhy(CapturedOutput output) throws Exception {
        String email = uniqueEmail();
        registerVerifiedUserAndLogin(email);
        String unverified = uniqueEmail();
        register(unverified, PASSWORD).andExpect(status().isOk());

        login(email, WRONG).andExpect(status().isUnauthorized());
        login(unverified, PASSWORD).andExpect(status().isForbidden());

        auditLine(output, "LOGIN_FAILED", user(email).getId(), "reason=WRONG_PASSWORD");
        auditLine(output, "LOGIN_FAILED", user(unverified).getId(), "reason=EMAIL_NOT_VERIFIED");
    }

    /** No id, and above all not the email someone typed. */
    @Test
    void anUnknownAccountIsRecordedWithoutItsEmail(CapturedOutput output) throws Exception {
        String unknown = uniqueEmail();
        String ip = randomIp();

        mvc.perform(loginRequest(unknown, WRONG).with(from(ip))).andExpect(status().isUnauthorized());

        assertThat(auditLines(output)).anyMatch(line -> line.contains("LOGIN_FAILED ip=" + ip + " reason=UNKNOWN_ACCOUNT"));
        assertThat(output.getOut()).doesNotContain(unknown).doesNotContain(WRONG);
    }

    @Test
    void lockedAccountsAndTooManyGuessesAreRecorded(CapturedOutput output) throws Exception {
        String email = uniqueEmail();
        registerVerifiedUserAndLogin(email);
        int userId = user(email).getId();
        String ip = randomIp();

        for (int i = 0; i < 5; i++)
            mvc.perform(loginRequest(email, WRONG).with(from(ip))).andExpect(status().isUnauthorized());
        mvc.perform(loginRequest(email, PASSWORD).with(from(ip))).andExpect(status().isTooManyRequests());
        jdbc.update("update users set locked_at = utc_timestamp(6) where id = ?", userId);
        login(email, PASSWORD).andExpect(status().isForbidden());

        auditLine(output, "LOGIN_FAILED", userId, "reason=RATE_LIMITED");
        auditLine(output, "LOGIN_FAILED", userId, "reason=ACCOUNT_LOCKED");
    }

    @Test
    void failedLoginsAreCounted() throws Exception {
        double before = count("LOGIN_FAILED", "WRONG_PASSWORD");
        String email = uniqueEmail();
        registerVerifiedUserAndLogin(email);

        login(email, WRONG).andExpect(status().isUnauthorized());
        login(email, WRONG).andExpect(status().isUnauthorized());

        assertThat(count("LOGIN_FAILED", "WRONG_PASSWORD")).isEqualTo(before + 2);
    }

    // ---- sessions ------------------------------------------------------------------

    @Test
    void logoutsAndEndedSessionsAreRecorded(CapturedOutput output) throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);
        int userId = user(email).getId();

        logout(refreshCookie(email, PASSWORD)).andExpect(status().isOk());
        refreshCookie(email, PASSWORD);
        long other = jdbc.queryForObject("select max(id) from user_sessions where user_id = ?", Long.class, userId);
        mvc.perform(as(accessToken, delete("/api/v1/users/me/sessions/" + other))).andExpect(status().isOk());
        mvc.perform(as(accessToken, delete("/api/v1/users/me/sessions"))).andExpect(status().isOk());

        auditLine(output, "LOGOUT", userId, "sessionId=");
        auditLine(output, "SESSION_ENDED", userId, "sessionId=" + other);
        auditLine(output, "ALL_SESSIONS_ENDED", userId, "");
    }

    @Test
    void aReusedRefreshTokenIsRecorded(CapturedOutput output) throws Exception {
        String email = uniqueEmail();
        registerVerifiedUserAndLogin(email);
        Cookie first = refreshCookie(email, PASSWORD);
        nextCookie(first);
        jdbc.update("update refresh_tokens set used_at = used_at - interval 1 minute where used_at is not null"
                + " and session_id in (select id from user_sessions where user_id = ?)", user(email).getId());

        refresh(first).andExpect(status().isUnauthorized());

        auditLine(output, "REFRESH_TOKEN_REUSED", user(email).getId(), "");
    }

    // ---- passwords and accounts ----------------------------------------------------

    @Test
    void passwordResetsAndDeletionsAreRecorded(CapturedOutput output) throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);
        int userId = user(email).getId();

        requestPasswordReset(email).andExpect(status().isOk());
        confirmPasswordReset(email, passwordResetOtp(email), NEW_PASSWORD).andExpect(status().isOk());
        accessToken = accessToken(email, NEW_PASSWORD);
        requestAccountDeletion(accessToken).andExpect(status().isOk());
        confirmAccountDeletion(accessToken, deleteAccountOtp(email), NEW_PASSWORD).andExpect(status().isOk());

        auditLine(output, "PASSWORD_RESET", userId, "");
        auditLine(output, "ACCOUNT_DELETED", userId, "");
        assertThat(auditLines(output)).noneMatch(line -> line.contains(email) || line.contains(NEW_PASSWORD));
    }

    @Test
    void passwordChangesAndWrongCurrentPasswordsAreRecorded(CapturedOutput output) throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);
        int userId = user(email).getId();
        long sessionId = claims(accessToken).get("sid", Long.class);

        mvc.perform(as(accessToken, put("/api/v1/users/me/password")).contentType(MediaType.APPLICATION_JSON)
                .content(changePassword(WRONG, NEW_PASSWORD))).andExpect(status().isForbidden());
        mvc.perform(as(accessToken, put("/api/v1/users/me/password")).contentType(MediaType.APPLICATION_JSON)
                .content(changePassword(PASSWORD, NEW_PASSWORD))).andExpect(status().isOk());

        auditLine(output, "PASSWORD_CONFIRMATION_FAILED", userId, "reason=WRONG_PASSWORD");
        auditLine(output, "PASSWORD_CHANGED", userId, "sessionId=" + sessionId);
        assertThat(auditLines(output)).noneMatch(line -> line.contains(email) || line.contains(NEW_PASSWORD)
                || line.contains(PASSWORD) || line.contains(WRONG));
    }

    @Test
    void emailChangesAndUndosAreRecordedWithoutTheAddresses(CapturedOutput output) throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);
        int userId = user(email).getId();
        String newEmail = uniqueEmail();

        mvc.perform(as(accessToken, post("/api/v1/users/me/email")).contentType(MediaType.APPLICATION_JSON)
                .content("{\"currentPassword\": \"%s\", \"newEmail\": \"%s\"}".formatted(PASSWORD, newEmail)))
                .andExpect(status().isOk());
        mvc.perform(as(accessToken, post("/api/v1/users/me/email/confirm")).contentType(MediaType.APPLICATION_JSON)
                .content("{\"otp\": \"%s\"}".formatted(emailChangeOtp(newEmail)))).andExpect(status().isOk());
        postJson("/api/v1/auth/email-change/undo", "{\"token\": \"%s\", \"password\": \"%s\"}"
                .formatted(undoEmailChangeToken(email), NEW_PASSWORD)).andExpect(status().isOk());

        auditLine(output, "EMAIL_CHANGED", userId, "");
        auditLine(output, "EMAIL_CHANGE_UNDONE", userId, "");
        assertThat(auditLines(output)).noneMatch(line -> line.contains(email) || line.contains(newEmail)
                || line.contains(NEW_PASSWORD));
    }

    // ---- admins --------------------------------------------------------------------

    @Test
    void adminActionsNameTheAdmin(CapturedOutput output) throws Exception {
        String adminEmail = uniqueEmail();
        String admin = registerVerifiedUserAndLogin(adminEmail);
        adminBootstrap.promote(List.of(adminEmail));
        int adminId = user(adminEmail).getId();
        String email = uniqueEmail();
        registerVerifiedUserAndLogin(email);
        int userId = user(email).getId();
        String users = "/api/v1/admin/users/" + userId;

        mvc.perform(as(admin, post(users + "/lock").contentType(MediaType.APPLICATION_JSON).content(password(WRONG))))
                .andExpect(status().isForbidden());
        mvc.perform(as(admin, post(users + "/lock").contentType(MediaType.APPLICATION_JSON).content(password(PASSWORD))))
                .andExpect(status().isOk());
        mvc.perform(as(admin, post(users + "/unlock").contentType(MediaType.APPLICATION_JSON).content(password(PASSWORD))))
                .andExpect(status().isOk());
        mvc.perform(as(admin, post(users + "/logout").contentType(MediaType.APPLICATION_JSON).content(password(PASSWORD))))
                .andExpect(status().isOk());
        mvc.perform(as(admin, put(users + "/role").contentType(MediaType.APPLICATION_JSON)
                .content("{\"role\": \"ADMIN\", \"password\": \"" + PASSWORD + "\"}"))).andExpect(status().isOk());

        auditLine(output, "PASSWORD_CONFIRMATION_FAILED", adminId, "reason=WRONG_PASSWORD");
        auditLine(output, "USER_LOCKED", userId, "by=" + adminId);
        auditLine(output, "USER_UNLOCKED", userId, "by=" + adminId);
        auditLine(output, "USER_LOGGED_OUT", userId, "by=" + adminId);
        auditLine(output, "ROLE_CHANGED", userId, "role=ADMIN by=" + adminId);
    }

    // ---- helpers -------------------------------------------------------------------

    /** The lines of the AUDIT logger. */
    private static List<String> auditLines(CapturedOutput output) {
        return output.getOut().lines().filter(line -> line.contains(" AUDIT ")).toList();
    }

    /** A line of this event and user that also contains {@code also}, and the client's address. */
    private static String auditLine(CapturedOutput output, String event, int userId, String also) {
        List<String> lines = auditLines(output).stream()
                .filter(line -> line.contains(event + " userId=" + userId + " ") && line.contains(also))
                .toList();
        assertThat(lines).as(event + " of user " + userId + " with " + also).isNotEmpty();
        assertThat(lines.getFirst()).containsPattern("ip=[0-9.]+");
        return lines.getFirst();
    }

    private double count(String event, String reason) {
        return meters.counter("authcore.audit_events", "event", event, "reason", reason).count();
    }

    private static MockHttpServletRequestBuilder loginRequest(String email, String password) {
        return post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\": \"%s\", \"password\": \"%s\"}".formatted(email, password));
    }

    private static String changePassword(String current, String newPassword) {
        return "{\"currentPassword\": \"%s\", \"newPassword\": \"%s\"}".formatted(current, newPassword);
    }

    private static String password(String password) {
        return "{\"password\": \"" + password + "\"}";
    }

    private static String randomIp() {
        ThreadLocalRandom random = ThreadLocalRandom.current();
        return "100." + random.nextInt(256) + "." + random.nextInt(256) + "." + random.nextInt(256);
    }
}
