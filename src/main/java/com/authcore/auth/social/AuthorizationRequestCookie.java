package com.authcore.auth.social;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.jspecify.annotations.Nullable;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.stereotype.Component;

import com.authcore.auth.common.AuthConfigProperties;

import io.jsonwebtoken.io.Decoders;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import tools.jackson.databind.json.JsonMapper;

/**
 * Keeps the sign-in request (its state, nonce and PKCE verifier) between sending the browser
 * to Google and Google sending it back, in a cookie instead of a server session: the API
 * keeps no sessions, and any of several servers may get the callback.
 *
 * <p>The cookie is encrypted (AES-GCM, with a key derived from the JWT key), so the browser
 * can neither read the verifier nor change anything, and HttpOnly. It's {@code SameSite=Lax},
 * which browsers send on Google's redirect back, unlike {@code Strict}. It lasts 5 minutes
 * and is only sent to the sign-in paths.
 */
@Component
@ConditionalOnExpression(GoogleSignInConfig.ENABLED)
class AuthorizationRequestCookie implements AuthorizationRequestRepository<OAuth2AuthorizationRequest> {
    static final String NAME = "oauth2Request";
    private static final Duration MAX_AGE = Duration.ofMinutes(5);
    private static final String PATH = "/api/v1/auth/oauth2";
    private static final int IV_BYTES = 12;
    private static final SecureRandom RANDOM = new SecureRandom();

    private final SecretKeySpec key;
    private final boolean secure;
    private final JsonMapper json = JsonMapper.builder().build();

    AuthorizationRequestCookie(AuthConfigProperties properties) {
        byte[] jwtKey = Decoders.BASE64.decode(properties.getToken().getSecretKey());
        this.key = new SecretKeySpec(hmac(jwtKey, "oauth2-request-cookie"), "AES");
        this.secure = properties.getCookie().isSecure();
    }

    @Override
    public @Nullable OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {
        String state = request.getParameter(OAuth2ParameterNames.STATE);
        OAuth2AuthorizationRequest saved = read(request);
        // The state in the redirect back must be the one this browser was sent off with.
        return saved != null && saved.getState().equals(state) ? saved : null;
    }

    @Override
    public void saveAuthorizationRequest(@Nullable OAuth2AuthorizationRequest authorizationRequest,
            HttpServletRequest request, HttpServletResponse response) {
        if (authorizationRequest == null) {
            write(response, "", Duration.ZERO);
            return;
        }
        write(response, encrypt(toJson(authorizationRequest)), MAX_AGE);
    }

    @Override
    public @Nullable OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request,
            HttpServletResponse response) {
        OAuth2AuthorizationRequest saved = loadAuthorizationRequest(request);
        write(response, "", Duration.ZERO);
        return saved;
    }

    private @Nullable OAuth2AuthorizationRequest read(HttpServletRequest request) {
        if (request.getCookies() == null)
            return null;
        for (Cookie cookie : request.getCookies()) {
            if (NAME.equals(cookie.getName())) {
                try {
                    return fromJson(decrypt(cookie.getValue()));
                } catch (RuntimeException e) {
                    return null; // made up, changed, or from another key
                }
            }
        }
        return null;
    }

    private void write(HttpServletResponse response, String value, Duration maxAge) {
        response.addHeader(HttpHeaders.SET_COOKIE, ResponseCookie.from(NAME, value)
                .httpOnly(true).secure(secure).sameSite("Lax").path(PATH).maxAge(maxAge).build().toString());
    }

    // ---- the request as JSON --------------------------------------------------------

    private String toJson(OAuth2AuthorizationRequest request) {
        Map<String, Object> fields = new HashMap<>();
        fields.put("authorizationUri", request.getAuthorizationUri());
        fields.put("clientId", request.getClientId());
        fields.put("redirectUri", request.getRedirectUri());
        fields.put("scopes", List.copyOf(request.getScopes()));
        fields.put("state", request.getState());
        fields.put("additionalParameters", request.getAdditionalParameters());
        fields.put("attributes", request.getAttributes());
        fields.put("authorizationRequestUri", request.getAuthorizationRequestUri());
        return json.writeValueAsString(fields);
    }

    @SuppressWarnings("unchecked")
    private OAuth2AuthorizationRequest fromJson(String text) {
        Map<String, Object> fields = json.readValue(text, Map.class);
        return OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri((String) fields.get("authorizationUri"))
                .clientId((String) fields.get("clientId"))
                .redirectUri((String) fields.get("redirectUri"))
                .scopes(new LinkedHashSet<>((List<String>) fields.get("scopes")))
                .state((String) fields.get("state"))
                .additionalParameters((Map<String, Object>) fields.get("additionalParameters"))
                .attributes((Map<String, Object>) fields.get("attributes"))
                .authorizationRequestUri((String) fields.get("authorizationRequestUri"))
                .build();
    }

    // ---- encryption -------------------------------------------------------------------

    private String encrypt(String text) {
        byte[] iv = new byte[IV_BYTES];
        RANDOM.nextBytes(iv);
        byte[] encrypted = cipher(Cipher.ENCRYPT_MODE, iv, text.getBytes(UTF_8));
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(ByteBuffer.allocate(IV_BYTES + encrypted.length).put(iv).put(encrypted).array());
    }

    private String decrypt(String value) {
        byte[] bytes = Base64.getUrlDecoder().decode(value);
        if (bytes.length <= IV_BYTES)
            throw new IllegalArgumentException("Too short");
        byte[] iv = new byte[IV_BYTES];
        System.arraycopy(bytes, 0, iv, 0, IV_BYTES);
        byte[] encrypted = new byte[bytes.length - IV_BYTES];
        System.arraycopy(bytes, IV_BYTES, encrypted, 0, encrypted.length);
        return new String(cipher(Cipher.DECRYPT_MODE, iv, encrypted), UTF_8);
    }

    private byte[] cipher(int mode, byte[] iv, byte[] input) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(mode, key, new GCMParameterSpec(128, iv));
            return cipher.doFinal(input);
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("Can't be decrypted", e);
        }
    }

    private static byte[] hmac(byte[] key, String text) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(text.getBytes(UTF_8));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e); // every Java has HmacSHA256
        }
    }
}
