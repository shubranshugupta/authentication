package com.authcore.auth.social;

import java.io.IOException;

import org.jspecify.annotations.Nullable;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Component;

import com.authcore.auth.audit.AuditEvent;
import com.authcore.auth.audit.AuditLog;
import com.authcore.auth.common.AuthConfigProperties;
import com.authcore.auth.session.ClientInfo;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * The browser's trip to Google and back (OpenID Connect, authorization code with PKCE),
 * done by Spring Security: it checks the state, the nonce and Google's signature on the ID
 * token. This decides what happens at the end: the browser goes to the web app's
 * {@code /login/google} page, with a one-minute code ({@code #code=...}) to exchange at
 * {@code POST /api/v1/auth/oauth2/exchange}, or the reason it failed ({@code #error=...}).
 * In the fragment, so that it's never sent to a server or in a Referer.
 */
@Slf4j
@Component
@ConditionalOnExpression(GoogleSignInConfig.ENABLED)
@RequiredArgsConstructor
public class GoogleSignIn {
    private static final String PAGE = "/login/google";

    private final ClientRegistrationRepository registrations;
    private final AuthorizationRequestCookie requestCookie;
    private final SocialLoginService socialLogin;
    private final AuthConfigProperties properties;
    private final AuditLog audit;

    /** Adds the sign-in endpoints to the security chain. */
    public void configure(HttpSecurity http) {
        DefaultOAuth2AuthorizationRequestResolver resolver = new DefaultOAuth2AuthorizationRequestResolver(
                registrations, GoogleSignInConfig.AUTHORIZATION);
        resolver.setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce());
        http.oauth2Login(login -> login
                // Also turns off the login page Spring would generate otherwise.
                .loginPage(GoogleSignInConfig.AUTHORIZATION + "/" + GoogleSignInConfig.GOOGLE)
                .authorizationEndpoint(endpoint -> endpoint
                        .baseUri(GoogleSignInConfig.AUTHORIZATION)
                        .authorizationRequestResolver(resolver)
                        .authorizationRequestRepository(requestCookie))
                .redirectionEndpoint(endpoint -> endpoint.baseUri(GoogleSignInConfig.CALLBACK + "*"))
                // Google's access token isn't needed after the sign-in: don't keep it.
                .authorizedClientRepository(new NotKept())
                .successHandler(this::succeeded)
                .failureHandler(this::failed));
    }

    private void succeeded(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException {
        if (!(authentication.getPrincipal() instanceof OidcUser user)) {
            redirect(response, "error", SocialLoginException.FAILED);
            return;
        }
        try {
            String code = socialLogin.signIn(new SocialLoginService.GoogleProfile(user.getSubject(), user.getEmail(),
                    Boolean.TRUE.equals(user.getEmailVerified()), user.getGivenName(), user.getFamilyName()),
                    ClientInfo.of(request));
            redirect(response, "code", code);
        } catch (SocialLoginException e) {
            audit.record(AuditEvent.LOGIN_FAILED, null, "reason", e.getReason(), "via", SocialLoginService.PROVIDER);
            redirect(response, "error", e.getReason());
        }
    }

    private void failed(HttpServletRequest request, HttpServletResponse response, AuthenticationException e)
            throws IOException {
        // Google's error code, e.g. access_denied when the user cancelled; never a token.
        String error = e instanceof OAuth2AuthenticationException oauth ? oauth.getError().getErrorCode() : "unknown";
        log.info("Google sign-in failed: {}", error);
        audit.record(AuditEvent.LOGIN_FAILED, null, "reason", SocialLoginException.FAILED, "via",
                SocialLoginService.PROVIDER, "error", error);
        redirect(response, "error", SocialLoginException.FAILED);
    }

    private void redirect(HttpServletResponse response, String name, String value) throws IOException {
        response.sendRedirect(properties.frontendPage(PAGE) + "#" + name + "=" + value);
    }

    /** Keeps no access tokens from Google: by default Spring would hold every one in memory. */
    private static final class NotKept implements OAuth2AuthorizedClientRepository {
        @Override
        public <T extends OAuth2AuthorizedClient> @Nullable T loadAuthorizedClient(String clientRegistrationId,
                @Nullable Authentication principal, HttpServletRequest request) {
            return null;
        }

        @Override
        public void saveAuthorizedClient(OAuth2AuthorizedClient authorizedClient, Authentication principal,
                HttpServletRequest request, HttpServletResponse response) {
        }

        @Override
        public void removeAuthorizedClient(String clientRegistrationId, @Nullable Authentication principal,
                HttpServletRequest request, HttpServletResponse response) {
        }
    }
}
