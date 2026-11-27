package com.authcore.auth.social;

import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ClientRegistrations;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.util.StringUtils;

import com.authcore.auth.common.AuthConfigProperties;

/**
 * Google as the one sign-in provider, when GOOGLE_CLIENT_ID is set. Without it, none of the
 * social login beans exist, and the application runs as before.
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnExpression(GoogleSignInConfig.ENABLED)
class GoogleSignInConfig {
    static final String ENABLED = "!'${auth.google.client-id:}'.isBlank()";
    static final String GOOGLE = "google";
    /** Where Google sends the browser back to; register it at Google with the API's host. */
    static final String CALLBACK = "/api/v1/auth/oauth2/callback/";
    /** Where the frontend sends the browser to start: {@code .../authorization/google}. */
    static final String AUTHORIZATION = "/api/v1/auth/oauth2/authorization";

    @Bean
    ClientRegistrationRepository clientRegistrationRepository(AuthConfigProperties properties) {
        AuthConfigProperties.GoogleConfigProperties google = properties.getGoogle();
        // Google's endpoints are well known, so it needs no network call at startup. Another
        // provider (in tests) is found through its discovery document.
        ClientRegistration.Builder builder = StringUtils.hasText(google.getIssuerUri())
                ? ClientRegistrations.fromOidcIssuerLocation(google.getIssuerUri()).registrationId(GOOGLE)
                        .scope("openid", "profile", "email")
                : CommonOAuth2Provider.GOOGLE.getBuilder(GOOGLE);
        return new InMemoryClientRegistrationRepository(builder
                .clientId(google.getClientId())
                .clientSecret(google.getClientSecret())
                .redirectUri("{baseUrl}" + CALLBACK + "{registrationId}")
                .build());
    }
}
