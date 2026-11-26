package com.authcore.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.test.web.servlet.ResultActions;

import com.authcore.auth.security.UserPrincipal;
import com.authcore.auth.support.IntegrationTest;
import com.authcore.auth.user.admin.AdminBootstrap;
import com.authcore.auth.user.Role;
import com.jayway.jsonpath.JsonPath;

/** H7: role names Spring can check, and the read-only admin API. */
class AdminUserTests extends IntegrationTest {
    private static final String USERS = "/api/v1/admin/users";

    @Autowired
    private AdminBootstrap adminBootstrap;

    // ---- roles ---------------------------------------------------------------------

    @Test
    void rolesHaveTheRolePrefixSpringExpects() throws Exception {
        String email = uniqueEmail();
        register(email, PASSWORD);

        assertThat(user(email).getRole()).isEqualTo(Role.USER);
        assertThat(UserPrincipal.from(user(email), 1L).getAuthorities()).extracting(GrantedAuthority::getAuthority)
                .containsExactly("ROLE_USER");
    }

    @Test
    void anEmailListedInAdminEmailsRegistersAsAdmin() throws Exception {
        String email = "first-admin@authcore.test"; // auth.admin-emails in application-test.yml
        String accessToken = registerVerifiedUserAndLogin(email);

        assertThat(user(email).getRole()).isEqualTo(Role.ADMIN);
        getAs(accessToken, USERS).andExpect(status().isOk());
    }

    @Test
    void startupPromotionMakesExistingListedUsersAdmins() throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);
        getAs(accessToken, USERS).andExpect(status().isForbidden());

        adminBootstrap.promote(List.of(email, "nobody-" + email));
        adminBootstrap.promote(List.of(email)); // promoting twice is harmless

        assertThat(user(email).getRole()).isEqualTo(Role.ADMIN);
        // The role is read from the database on each request, so the same token now works.
        getAs(accessToken, USERS).andExpect(status().isOk());
    }

    // ---- access control ------------------------------------------------------------

    @Test
    void regularUsersGet403() throws Exception {
        String accessToken = registerVerifiedUserAndLogin(uniqueEmail());

        getAs(accessToken, USERS).andExpect(status().isForbidden());
        getAs(accessToken, USERS + "/1").andExpect(status().isForbidden());
    }

    @Test
    void requestsWithoutATokenGet401() throws Exception {
        mvc.perform(get(USERS)).andExpect(status().isUnauthorized());
    }

    // ---- admin API -----------------------------------------------------------------

    @Test
    void adminsCanListUsersWithoutPasswords() throws Exception {
        String admin = createAdminAndLogin();
        String alice = uniqueEmail();
        String bob = uniqueEmail();
        register(alice, PASSWORD);
        register(bob, PASSWORD);

        // Every page: other test classes share the database, so there may be more users
        // than fit on one, and new ones (the highest ids) come last.
        List<String> emails = new ArrayList<>();
        int totalPages;
        int page = 0;
        do {
            String body = getAs(admin, USERS + "?size=100&page=" + page)
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.page").value(page))
                    .andExpect(jsonPath("$.size").value(100))
                    .andExpect(jsonPath("$.users[*].password").isEmpty())
                    .andExpect(jsonPath("$.users[0].role").exists())
                    .andReturn().getResponse().getContentAsString();
            emails.addAll(JsonPath.read(body, "$.users[*].email"));
            totalPages = JsonPath.read(body, "$.totalPages");
        } while (++page < totalPages);

        assertThat(emails).contains(alice, bob).doesNotHaveDuplicates();
    }

    @Test
    void pageSizeIsCappedAt100() throws Exception {
        String admin = createAdminAndLogin();

        getAs(admin, USERS + "?size=5000&page=-3")
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.size").value(100))
                .andExpect(jsonPath("$.page").value(0));
    }

    @Test
    void adminsCanGetOneUser() throws Exception {
        String admin = createAdminAndLogin();
        String email = uniqueEmail();
        register(email, PASSWORD);
        int id = user(email).getId();

        getAs(admin, USERS + "/" + id)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(id))
                .andExpect(jsonPath("$.email").value(email))
                .andExpect(jsonPath("$.role").value("USER"))
                .andExpect(jsonPath("$.emailVerified").value(false))
                .andExpect(jsonPath("$.password").doesNotExist());
    }

    @Test
    void unknownUserIdReturns404() throws Exception {
        String admin = createAdminAndLogin();

        getAs(admin, USERS + "/999999999").andExpect(status().isNotFound());
    }

    // ---- helpers -------------------------------------------------------------------

    private String createAdminAndLogin() throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);
        adminBootstrap.promote(List.of(email));
        return accessToken;
    }

    private ResultActions getAs(String accessToken, String path) throws Exception {
        return mvc.perform(get(path).header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken));
    }
}
