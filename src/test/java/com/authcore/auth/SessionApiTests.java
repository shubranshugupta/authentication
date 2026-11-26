package com.authcore.auth;

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import com.authcore.auth.support.IntegrationTest;

/** A6: users see where they are logged in, and can log out there. */
class SessionApiTests extends IntegrationTest {
    private static final String SESSIONS = "/api/v1/users/me/sessions";

    // ---- list ----------------------------------------------------------------------

    @Test
    void sessionsAreListedWithTheCurrentOneMarked() throws Exception {
        String email = uniqueEmail();
        String first = registerVerifiedUserAndLogin(email);
        ResultActions phone = loginFrom(email, "203.0.113.7", "Phone");

        listSessions(accessToken(phone))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(2)))
                .andExpect(jsonPath("$[0].id").value(sid(accessToken(phone))))
                .andExpect(jsonPath("$[0].device").value("Phone"))
                .andExpect(jsonPath("$[0].ip").value("203.0.113.7"))
                .andExpect(jsonPath("$[0].createdAt").isNotEmpty())
                .andExpect(jsonPath("$[0].lastUsedAt").isNotEmpty())
                .andExpect(jsonPath("$[0].expiresAt").isNotEmpty())
                .andExpect(jsonPath("$[0].current").value(true))
                .andExpect(jsonPath("$[1].id").value(sid(first)))
                .andExpect(jsonPath("$[1].current").value(false));
        listSessions(first).andExpect(jsonPath("$[1].current").value(true));
    }

    @Test
    void theListHasNoTokensAndNobodyElsesSessions() throws Exception {
        registerVerifiedUserAndLogin(uniqueEmail());
        String accessToken = registerVerifiedUserAndLogin(uniqueEmail());

        listSessions(accessToken)
                .andExpect(jsonPath("$", hasSize(1)))
                .andExpect(jsonPath("$[0].keys()", containsInAnyOrder(
                        "id", "device", "ip", "createdAt", "lastUsedAt", "expiresAt", "current")));
    }

    @Test
    void expiredSessionsAreNotListed() throws Exception {
        String email = uniqueEmail();
        String old = registerVerifiedUserAndLogin(email);
        String current = accessToken(email, PASSWORD);
        jdbc.update("update user_sessions set expires_at = '2020-01-01' where id = ?", sid(old));

        listSessions(current).andExpect(jsonPath("$", hasSize(1))).andExpect(jsonPath("$[0].id").value(sid(current)));
    }

    // ---- end one -------------------------------------------------------------------

    @Test
    void endingASessionLogsThatDeviceOut() throws Exception {
        String email = uniqueEmail();
        String laptop = registerVerifiedUserAndLogin(email);
        ResultActions phone = login(email, PASSWORD);

        mvc.perform(as(laptop, delete(SESSIONS + "/" + sid(accessToken(phone)))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.msg").value("Session ended."));

        getProfile(accessToken(phone)).andExpect(status().isUnauthorized());
        refresh(refreshCookie(phone)).andExpect(status().isUnauthorized());
        getProfile(laptop).andExpect(status().isOk());
    }

    @Test
    void theCurrentSessionCanBeEndedToo() throws Exception {
        String accessToken = registerVerifiedUserAndLogin(uniqueEmail());

        mvc.perform(as(accessToken, delete(SESSIONS + "/" + sid(accessToken)))).andExpect(status().isOk());

        getProfile(accessToken).andExpect(status().isUnauthorized());
    }

    /** The same answer as for a session that doesn't exist. */
    @Test
    void nobodyCanEndSomebodyElsesSession() throws Exception {
        String victim = registerVerifiedUserAndLogin(uniqueEmail());
        String attacker = registerVerifiedUserAndLogin(uniqueEmail());

        for (long id : new long[] { sid(victim), 999999999 })
            mvc.perform(as(attacker, delete(SESSIONS + "/" + id)))
                    .andExpect(status().isNotFound())
                    .andExpect(jsonPath("$.code").value("SESSION_NOT_FOUND"))
                    .andExpect(jsonPath("$.detail").value("Session " + id + " not found"));

        getProfile(victim).andExpect(status().isOk());
    }

    // ---- end all -------------------------------------------------------------------

    @Test
    void endingAllSessionsLogsOutEverywhere() throws Exception {
        String email = uniqueEmail();
        String laptop = registerVerifiedUserAndLogin(email);
        ResultActions phone = login(email, PASSWORD);
        String other = registerVerifiedUserAndLogin(uniqueEmail());

        mvc.perform(as(laptop, delete(SESSIONS)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.msg").value("Logged out of all devices."));

        getProfile(laptop).andExpect(status().isUnauthorized());
        getProfile(accessToken(phone)).andExpect(status().isUnauthorized());
        refresh(refreshCookie(phone)).andExpect(status().isUnauthorized());
        getProfile(other).andExpect(status().isOk());
        getProfile(accessToken(email, PASSWORD)).andExpect(status().isOk());
    }

    @Test
    void everythingNeedsALogin() throws Exception {
        mvc.perform(get(SESSIONS)).andExpect(status().isUnauthorized());
        mvc.perform(delete(SESSIONS)).andExpect(status().isUnauthorized());
        mvc.perform(delete(SESSIONS + "/1")).andExpect(status().isUnauthorized());
    }

    // ---- helpers -------------------------------------------------------------------

    private Long sid(String accessToken) {
        return claims(accessToken).get("sid", Long.class);
    }

    private ResultActions loginFrom(String email, String ip, String device) throws Exception {
        return mvc.perform(MockMvcRequestBuilders.post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"email": "%s", "password": "%s"}
                        """.formatted(email, PASSWORD))
                .header(HttpHeaders.USER_AGENT, device)
                .with(request -> {
                    request.setRemoteAddr(ip);
                    return request;
                }));
    }
}
