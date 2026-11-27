package com.authcore.auth.social;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

import com.authcore.auth.common.AuthConfigProperties;

import jakarta.servlet.http.Cookie;

class AuthorizationRequestCookieTests {
    private static final String KEY = "dGVzdC1vbmx5LWp3dC1zaWduaW5nLWtleS1mb3ItYXV0aGNvcmUtaW50ZWdyYXRpb24tdGVzdHM=";

    private final AuthorizationRequestCookie repository = repository(KEY);

    @Test
    void theRequestComesBackWithEverythingInIt() {
        OAuth2AuthorizationRequest saved = request("the-state");

        OAuth2AuthorizationRequest loaded = repository.loadAuthorizationRequest(callback("the-state", save(saved)));

        assertThat(loaded).isNotNull();
        assertThat(loaded.getState()).isEqualTo("the-state");
        assertThat(loaded.getAttributes()).isEqualTo(saved.getAttributes());
        assertThat(loaded.getAdditionalParameters()).isEqualTo(saved.getAdditionalParameters());
        assertThat(loaded.getScopes()).isEqualTo(saved.getScopes());
        assertThat(loaded.getRedirectUri()).isEqualTo(saved.getRedirectUri());
        assertThat(loaded.getAuthorizationRequestUri()).isEqualTo(saved.getAuthorizationRequestUri());
    }

    @Test
    void anotherStateFindsNothing() {
        Cookie cookie = save(request("the-state"));

        assertThat(repository.loadAuthorizationRequest(callback("another-state", cookie))).isNull();
        assertThat(repository.loadAuthorizationRequest(callback(null, cookie))).isNull();
    }

    @Test
    void aChangedCookieOrAnotherKeyFindsNothing() {
        Cookie cookie = save(request("the-state"));
        String value = cookie.getValue();
        Cookie changed = new Cookie(cookie.getName(), value.substring(0, 20) + (value.charAt(20) == 'A' ? 'B' : 'A')
                + value.substring(21));

        assertThat(repository.loadAuthorizationRequest(callback("the-state", changed))).isNull();
        assertThat(repository("b3RoZXIta2V5LWZvci10ZXN0cy1vbmx5LXRoYXQtaXMtbG9uZy1lbm91Z2gh")
                .loadAuthorizationRequest(callback("the-state", cookie))).isNull();
        assertThat(repository.loadAuthorizationRequest(callback("the-state", new Cookie(cookie.getName(), "junk"))))
                .isNull();
        assertThat(repository.loadAuthorizationRequest(callback("the-state"))).isNull();
    }

    @Test
    void theCookieDoesNotShowTheVerifierOrTheState() {
        Cookie cookie = save(request("the-state"));

        assertThat(cookie.getValue()).doesNotContain("the-state", "the-verifier");
    }

    @Test
    void removingDeletesTheCookie() {
        Cookie cookie = save(request("the-state"));
        MockHttpServletResponse response = new MockHttpServletResponse();

        assertThat(repository.removeAuthorizationRequest(callback("the-state", cookie), response)).isNotNull();
        assertThat(response.getHeader(HttpHeaders.SET_COOKIE)).startsWith(AuthorizationRequestCookie.NAME + "=;")
                .contains("Max-Age=0");
    }

    private Cookie save(OAuth2AuthorizationRequest request) {
        MockHttpServletResponse response = new MockHttpServletResponse();
        repository.saveAuthorizationRequest(request, new MockHttpServletRequest(), response);
        String header = response.getHeader(HttpHeaders.SET_COOKIE);
        assertThat(header).contains("HttpOnly", "SameSite=Lax", "Path=/api/v1/auth/oauth2", "Max-Age=300");
        return new Cookie(AuthorizationRequestCookie.NAME, header.substring(header.indexOf('=') + 1, header.indexOf(';')));
    }

    private static MockHttpServletRequest callback(String state, Cookie... cookies) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/auth/oauth2/callback/google");
        if (state != null)
            request.setParameter("state", state);
        if (cookies.length > 0)
            request.setCookies(cookies);
        return request;
    }

    private static OAuth2AuthorizationRequest request(String state) {
        return OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri("https://accounts.google.com/o/oauth2/v2/auth")
                .clientId("client")
                .redirectUri("https://api.example.com/api/v1/auth/oauth2/callback/google")
                .scopes(Set.of("openid", "email"))
                .state(state)
                .additionalParameters(Map.of("nonce", "hashed-nonce", "code_challenge", "challenge",
                        "code_challenge_method", "S256"))
                .attributes(Map.of("registration_id", "google", "nonce", "the-nonce", "code_verifier", "the-verifier"))
                .authorizationRequestUri("https://accounts.google.com/o/oauth2/v2/auth?state=" + state)
                .build();
    }

    private static AuthorizationRequestCookie repository(String jwtKey) {
        AuthConfigProperties properties = new AuthConfigProperties();
        properties.getToken().setSecretKey(jwtKey);
        return new AuthorizationRequestCookie(properties);
    }
}
