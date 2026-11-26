package com.authcore.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.cookie;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.ResultActions;

import com.authcore.auth.support.IntegrationTest;

import jakarta.servlet.http.Cookie;

/**
 * C2: a session per login, refresh tokens that work once, and logout. Until Phase 5 every
 * device had the same refresh token, which stayed the same and couldn't be revoked.
 */
class SessionTests extends IntegrationTest {
    private static final String NEW_PASSWORD = "N3w-Str0ng-Passw0rd!";

    // ---- storage -------------------------------------------------------------------

    @Test
    void onlyHashesOfRefreshTokensAreStored() throws Exception {
        String email = verifiedUser();
        Cookie cookie = refreshCookie(email, PASSWORD);

        List<String> hashes = jdbc.queryForList("select token_hash from refresh_tokens t"
                + " join user_sessions s on s.id = t.session_id where s.user_id = ?", String.class, user(email).getId());

        assertThat(hashes).hasSize(1).allSatisfy(hash -> assertThat(hash).hasSize(64).doesNotContain(cookie.getValue()));
        assertThat(cookie.getValue()).hasSize(43);
    }

    @Test
    void aSessionRemembersWhereItWasLastUsed() throws Exception {
        String email = verifiedUser();
        Cookie cookie = refreshCookie(loginFrom("203.0.113.7", "Firefox " + "x".repeat(300), email));

        assertThat(jdbc.queryForMap("select ip, device from user_sessions where user_id = ?", user(email).getId()))
                .containsEntry("ip", "203.0.113.7")
                .containsEntry("device", "Firefox " + "x".repeat(247));

        mvc.perform(post("/api/v1/auth/refresh").cookie(cookie).with(from("2001:db8::1"))).andExpect(status().isOk());

        assertThat(jdbc.queryForMap("select ip, device from user_sessions where user_id = ?", user(email).getId()))
                .containsEntry("ip", "2001:db8::1")
                .containsEntry("device", null);
    }

    // ---- rotation ------------------------------------------------------------------

    @Test
    void everyRefreshReplacesTheToken() throws Exception {
        String email = verifiedUser();
        Cookie first = refreshCookie(email, PASSWORD);

        Cookie second = nextCookie(first);
        Cookie third = nextCookie(second);

        assertThat(List.of(first.getValue(), second.getValue(), third.getValue())).doesNotHaveDuplicates();
        getProfile(accessToken(refresh(third))).andExpect(status().isOk()).andExpect(jsonPath("$.email").value(email));
        assertThat(sessions(email)).isEqualTo(1);
    }

    @Test
    void theNewCookieIsLikeTheFirstOne() throws Exception {
        String setCookie = refresh(refreshCookie(verifiedUser(), PASSWORD))
                .andExpect(cookie().httpOnly("refreshToken", true))
                .andExpect(cookie().secure("refreshToken", true))
                .andExpect(cookie().sameSite("refreshToken", "Strict"))
                .andExpect(cookie().maxAge("refreshToken", 604800))
                .andReturn().getResponse().getHeader(HttpHeaders.SET_COOKIE);

        assertThat(setCookie).contains("Path=/api/v1/auth;");
    }

    /** Somebody has a copy, and nobody can tell which of the two is the owner. */
    @Test
    void aUsedTokenThatShowsUpAgainEndsEverySessionOfTheUser() throws Exception {
        String email = verifiedUser();
        ResultActions otherDevice = login(email, PASSWORD);
        Cookie stolen = refreshCookie(email, PASSWORD);
        ResultActions refreshed = refresh(stolen);
        Cookie current = refreshCookie(refreshed);
        usedAWhileAgo(email);

        refresh(stolen).andExpect(status().isUnauthorized()).andExpect(jsonPath("$.code").value("INVALID_TOKEN"));

        assertThat(sessions(email)).isZero();
        refresh(current).andExpect(status().isUnauthorized());
        refresh(refreshCookie(otherDevice)).andExpect(status().isUnauthorized());
        getProfile(accessToken(refreshed)).andExpect(status().isUnauthorized());
        getProfile(accessToken(otherDevice)).andExpect(status().isUnauthorized());
        login(email, PASSWORD).andExpect(status().isOk());
    }

    @Test
    void aTokenUsedTwoRefreshesAgoIsACopyToo() throws Exception {
        String email = verifiedUser();
        Cookie first = refreshCookie(email, PASSWORD);
        Cookie third = nextCookie(nextCookie(first));
        usedAWhileAgo(email);

        refresh(first).andExpect(status().isUnauthorized());
        refresh(third).andExpect(status().isUnauthorized());
    }

    @Test
    void anotherUsersSessionsSurvive() throws Exception {
        Cookie other = refreshCookie(verifiedUser(), PASSWORD);
        String email = verifiedUser();
        Cookie stolen = refreshCookie(email, PASSWORD);
        nextCookie(stolen);
        usedAWhileAgo(email);

        refresh(stolen).andExpect(status().isUnauthorized());

        refresh(other).andExpect(status().isOk());
    }

    /** Two tabs can refresh at the same moment, with the same cookie. */
    @Test
    void aTokenUsedAMomentAgoStillGetsAnAccessTokenButNoNewCookie() throws Exception {
        String email = verifiedUser();
        Cookie first = refreshCookie(email, PASSWORD);
        Cookie second = nextCookie(first);

        ResultActions again = refresh(first).andExpect(cookie().doesNotExist("refreshToken"));

        getProfile(accessToken(again)).andExpect(status().isOk());
        refresh(second).andExpect(status().isOk());
    }

    // ---- expiry --------------------------------------------------------------------

    @Test
    void aSessionNotUsedForAWeekHasExpired() throws Exception {
        String email = verifiedUser();
        ResultActions login = login(email, PASSWORD);
        jdbc.update("update user_sessions set expires_at = '2020-01-01' where user_id = ?", user(email).getId());

        getProfile(accessToken(login)).andExpect(status().isUnauthorized());
        refresh(refreshCookie(login)).andExpect(status().isUnauthorized()).andExpect(jsonPath("$.code").value("TOKEN_EXPIRED"));
        assertThat(sessions(email)).isZero();
    }

    @Test
    void usingASessionExtendsItButNotBeyond30Days() throws Exception {
        String email = verifiedUser();
        Cookie cookie = refreshCookie(email, PASSWORD);
        loggedInDaysAgo(email, 20);
        cookie = nextCookie(cookie);
        assertThat(cookie.getMaxAge()).isEqualTo(7 * 24 * 60 * 60);

        loggedInDaysAgo(email, 29);
        cookie = nextCookie(cookie);
        assertThat(cookie.getMaxAge()).isBetween(24 * 60 * 60 - 60, 24 * 60 * 60);

        loggedInDaysAgo(email, 30);
        jdbc.update("update user_sessions set expires_at = created_at + interval 30 day where user_id = ?", user(email).getId());
        refresh(cookie).andExpect(status().isUnauthorized());
    }

    @Test
    void aLoginDeletesTheUsersExpiredSessions() throws Exception {
        String email = verifiedUser();
        login(email, PASSWORD);
        jdbc.update("update user_sessions set expires_at = '2020-01-01' where user_id = ?", user(email).getId());
        login(email, PASSWORD);

        assertThat(sessions(email)).isEqualTo(1);
    }

    // ---- several devices -----------------------------------------------------------

    @Test
    void everyLoginHasItsOwnSession() throws Exception {
        String email = verifiedUser();
        ResultActions phone = login(email, PASSWORD);
        ResultActions laptop = login(email, PASSWORD);

        assertThat(refreshCookie(phone).getValue()).isNotEqualTo(refreshCookie(laptop).getValue());
        assertThat(claims(accessToken(phone)).get("sid", Long.class)).isNotEqualTo(claims(accessToken(laptop)).get("sid", Long.class));
        assertThat(sessions(email)).isEqualTo(2);
    }

    // ---- logout --------------------------------------------------------------------

    @Test
    void logoutEndsTheSessionAndDeletesTheCookie() throws Exception {
        String email = verifiedUser();
        ResultActions login = login(email, PASSWORD);
        getProfile(accessToken(login)).andExpect(status().isOk());

        String setCookie = logout(refreshCookie(login))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.msg").value("Logged out"))
                .andExpect(cookie().value("refreshToken", ""))
                .andExpect(cookie().maxAge("refreshToken", 0))
                .andReturn().getResponse().getHeader(HttpHeaders.SET_COOKIE);

        // Browsers only replace a cookie if these are the same.
        assertThat(setCookie).contains("Path=/api/v1/auth;").contains("Secure").contains("SameSite=Strict");
        refresh(refreshCookie(login)).andExpect(status().isUnauthorized());
        getProfile(accessToken(login)).andExpect(status().isUnauthorized()).andExpect(jsonPath("$.code").value("INVALID_TOKEN"));
        assertThat(sessions(email)).isZero();
    }

    @Test
    void logoutEndsOnlyThatSession() throws Exception {
        String email = verifiedUser();
        ResultActions phone = login(email, PASSWORD);
        ResultActions laptop = login(email, PASSWORD);

        logout(refreshCookie(phone)).andExpect(status().isOk());

        getProfile(accessToken(phone)).andExpect(status().isUnauthorized());
        getProfile(accessToken(laptop)).andExpect(status().isOk());
        refresh(refreshCookie(laptop)).andExpect(status().isOk());
    }

    /** Every access token of the session, also those from before a refresh. */
    @Test
    void logoutEndsOlderAccessTokensToo() throws Exception {
        ResultActions login = login(verifiedUser(), PASSWORD);
        Cookie current = nextCookie(refreshCookie(login));
        getProfile(accessToken(login)).andExpect(status().isOk());

        logout(current).andExpect(status().isOk());

        getProfile(accessToken(login)).andExpect(status().isUnauthorized());
    }

    @Test
    void logoutAlwaysSucceeds() throws Exception {
        Cookie cookie = refreshCookie(verifiedUser(), PASSWORD);

        logout(cookie).andExpect(status().isOk());
        logout(cookie).andExpect(status().isOk());
        logout(new Cookie("refreshToken", "never-existed")).andExpect(status().isOk());
        mvc.perform(post("/api/v1/auth/logout")).andExpect(status().isOk());
    }

    @Test
    void logoutNeedsAPost() throws Exception {
        mvc.perform(get("/api/v1/auth/logout")).andExpect(status().isMethodNotAllowed());
    }

    // ---- password reset and deletion -----------------------------------------------

    @Test
    void aPasswordResetEndsEverySession() throws Exception {
        String email = verifiedUser();
        ResultActions phone = login(email, PASSWORD);
        ResultActions laptop = login(email, PASSWORD);

        requestPasswordReset(email).andExpect(status().isOk());
        confirmPasswordReset(email, passwordResetOtp(email), NEW_PASSWORD).andExpect(status().isOk());

        assertThat(sessions(email)).isZero();
        for (ResultActions login : List.of(phone, laptop)) {
            refresh(refreshCookie(login)).andExpect(status().isUnauthorized());
            getProfile(accessToken(login)).andExpect(status().isUnauthorized());
        }
    }

    @Test
    void deletingTheUserDeletesTheirSessions() throws Exception {
        String email = verifiedUser();
        Cookie cookie = refreshCookie(email, PASSWORD);
        nextCookie(cookie);
        Integer id = user(email).getId();

        userRepository.deleteById(id);

        assertThat(jdbc.queryForObject("select count(*) from user_sessions where user_id = ?", Integer.class, id)).isZero();
        assertThat(jdbc.queryForObject("select count(*) from refresh_tokens t"
                + " left join user_sessions s on s.id = t.session_id where s.id is null", Integer.class)).isZero();
    }

    // ---- access tokens on public endpoints -----------------------------------------

    /** A client that always sends its access token couldn't refresh it once it expired. */
    @Test
    void publicEndpointsIgnoreAccessTokens() throws Exception {
        Cookie cookie = refreshCookie(verifiedUser(), PASSWORD);

        mvc.perform(as("not-a-jwt", post("/api/v1/auth/refresh").cookie(cookie))).andExpect(status().isOk());
        mvc.perform(as("not-a-jwt", post("/api/v1/auth/logout").cookie(cookie))).andExpect(status().isOk());
    }

    /** A path that only looks public doesn't get past the login. */
    @Test
    void otherPathsStillNeedOne() throws Exception {
        for (String path : List.of("/api/v1/authx", "/api/v1/users/me", "/api/v1/auth/../users/me", "/api/v1/users/me/api/v1/auth/x"))
            assertThat(mvc.perform(get(java.net.URI.create(path))).andReturn().getResponse().getStatus()).as(path).isIn(400, 401);
    }

    // ---- helpers -------------------------------------------------------------------

    /** Without a session. */
    private String verifiedUser() throws Exception {
        String email = uniqueEmail();
        register(email, PASSWORD).andExpect(status().isOk());
        verifyEmail(verificationToken(email)).andExpect(status().isOk());
        return email;
    }

    private ResultActions loginFrom(String ip, String device, String email) throws Exception {
        return mvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\": \"%s\", \"password\": \"%s\"}".formatted(email, PASSWORD))
                .header(HttpHeaders.USER_AGENT, device).with(from(ip)));
    }

    private int sessions(String email) {
        return jdbc.queryForObject("select count(*) from user_sessions where user_id = ?", Integer.class, user(email).getId());
    }

    /** As if the last refresh had been longer ago than the grace period. */
    private void usedAWhileAgo(String email) {
        jdbc.update("update refresh_tokens t join user_sessions s on s.id = t.session_id"
                + " set t.used_at = t.used_at - interval 11 second where s.user_id = ?", user(email).getId());
    }

    private void loggedInDaysAgo(String email, int days) {
        jdbc.update("update user_sessions set created_at = utc_timestamp(6) - interval ? day where user_id = ?",
                days, user(email).getId());
    }
}
