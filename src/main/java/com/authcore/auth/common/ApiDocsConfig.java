package com.authcore.auth.common;

import org.springframework.context.annotation.Configuration;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityScheme;

/**
 * The OpenAPI description of the API (F3): /v3/api-docs, and Swagger UI at
 * /swagger-ui.html. Off in prod unless API_DOCS_ENABLED=true.
 *
 * <p>Every endpoint needs an access token ("bearer"), except those that say otherwise
 * (the ones under /api/v1/auth).
 */
@Configuration
@OpenAPIDefinition(
        info = @Info(title = "AuthCore API", version = "v1",
                description = "Registration, login, sessions and account management. Errors are "
                        + "RFC 9457 problem details with a stable \"code\"; see README.md."),
        security = @SecurityRequirement(name = ApiDocsConfig.BEARER))
@SecurityScheme(name = ApiDocsConfig.BEARER, type = SecuritySchemeType.HTTP, scheme = "bearer", bearerFormat = "JWT",
        description = "The accessToken from POST /api/v1/auth/login or /api/v1/auth/refresh.")
public class ApiDocsConfig {
    public static final String BEARER = "bearer";
}
