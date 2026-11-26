package com.authcore.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.env.PropertySource;
import org.springframework.core.io.ClassPathResource;

import com.authcore.auth.support.IntegrationTest;

/** F3: the OpenAPI description and Swagger UI. */
class ApiDocsTests extends IntegrationTest {

    @Test
    void theApiIsDescribedWithItsLoginScheme() throws Exception {
        mvc.perform(get("/v3/api-docs"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.info.title").value("AuthCore API"))
                .andExpect(jsonPath("$.components.securitySchemes.bearer.scheme").value("bearer"))
                .andExpect(jsonPath("$.paths['/api/v1/auth/login'].post").exists())
                .andExpect(jsonPath("$.paths['/api/v1/users/me/sessions'].get").exists())
                .andExpect(jsonPath("$.paths['/api/v1/admin/users/{id}/role'].put").exists())
                // The login needs no token; the others do (the default).
                .andExpect(jsonPath("$.paths['/api/v1/auth/login'].post.security", empty()))
                .andExpect(jsonPath("$.paths['/api/v1/users/me/sessions'].get.security").doesNotExist())
                .andExpect(jsonPath("$.security[0].bearer").exists());
    }

    /** Request bodies are described with their rules, e.g. the admin's password. */
    @Test
    void requestBodiesHaveTheirRules() throws Exception {
        mvc.perform(get("/v3/api-docs"))
                .andExpect(jsonPath("$.components.schemas.ChangeRoleRequest.required").value(
                        org.hamcrest.Matchers.containsInAnyOrder("role", "password")));
    }

    @Test
    void swaggerUiIsServedWithoutALogin() throws Exception {
        mvc.perform(get("/swagger-ui/index.html")).andExpect(status().isOk());
    }

    /** Off in production unless API_DOCS_ENABLED=true: it maps out the whole API. */
    @Test
    void productionHasNoApiDocsByDefault() throws Exception {
        PropertySource<?> prod = new YamlPropertySourceLoader()
                .load("prod", new ClassPathResource("application-prod.yml")).getFirst();

        assertThat(prod.getProperty("springdoc.api-docs.enabled")).isEqualTo("${API_DOCS_ENABLED:false}");
        assertThat(prod.getProperty("springdoc.swagger-ui.enabled")).isEqualTo("${API_DOCS_ENABLED:false}");
    }
}
