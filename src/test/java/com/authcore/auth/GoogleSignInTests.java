package com.authcore.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.ResultActions;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;

import com.authcore.auth.mfa.Totp;
import com.authcore.auth.support.IntegrationTest;
import com.jayway.jsonpath.JsonPath;

import jakarta.servlet.http.Cookie;

/**
 * F5: signing in with Google. A mock OpenID provider stands in for Google: the tests go the
 * browser's way (to the provider, signing in there, back to the callback, then the web app's
 * exchange), with the person's claims chosen by each test.
 */
@ExtendWith(OutputCaptureExtension.class)
class GoogleSignInTests extends IntegrationTest {
    private static final String LINKED = "Google sign-in was added to your AuthCore account";
    private static final String FRONTEND_PAGE = "https://app.authcore.test/login/google#";

    /** Started once for this class; Testcontainers removes it when the test JVM exits. */
    private static final GenericContainer<?> PROVIDER = new GenericContainer<>(
            DockerImageName.parse("ghcr.io/navikt/mock-oauth2-server:2.1.10"))
            .withExposedPorts(8080)
            // A login form that takes the claims, so each test picks who signs in.
            .withEnv("JSON_CONFIG", "{\"interactiveLogin\": true}")
            .waitingFor(Wait.forHttp("/google/.well-known/openid-configuration").forStatusCode(200));

    static {
        PROVIDER.start();
    }

    @DynamicPropertySource
    static void googleProperties(DynamicPropertyRegistry registry) {
        registry.add("auth.google.client-id", () -> "authcore-test");
        registry.add("auth.google.client-secret", () -> "test-secret");
        registry.add("auth.google.issuer-uri",
                () -> "http://" + PROVIDER.getHost() + ":" + PROVIDER.getMappedPort(8080) + "/google");
    }

    private final HttpClient http = HttpClient.newHttpClient();

    // ---- new and known accounts ------------------------------------------------------------

    @Test
    void aNewPersonGetsAnAccountAndIsLoggedIn() throws Exception {
        String email = uniqueEmail();

        ResultActions login = exchange(signIn(person(email)).get("code"));

        login.andExpect(status().isOk()).andExpect(jsonPath("$.accessToken").isNotEmpty());
        getProfile(accessToken(login))
                .andExpect(jsonPath("$.email").value(email))
                .andExpect(jsonPath("$.firstName").value("Jane"))
                .andExpect(jsonPath("$.lastName").value("Doe"));
        refresh(refreshCookie(login)).andExpect(status().isOk());
        assertThat(user(email).isEnabled()).isTrue();
        // No password anybody knows.
        login(email, PASSWORD).andExpect(status().isUnauthorized());
    }

    @Test
    void theSameGoogleAccountSignsInToTheSameAccountEvenAfterAnEmailChange() throws Exception {
        String email = uniqueEmail();
        String subject = UUID.randomUUID().toString();
        exchange(signIn(subject, person(email)).get("code")).andExpect(status().isOk());
        String newEmail = uniqueEmail();
        jdbc.update("update users set email = ? where email = ?", newEmail, email);

        ResultActions again = exchange(signIn(subject, person("other-" + email)).get("code"));

        getProfile(accessToken(again)).andExpect(jsonPath("$.email").value(newEmail));
        assertThat(jdbc.queryForObject("select count(*) from users where email = ?", Integer.class, "other-" + email))
                .isZero();
    }

    @Test
    void anUnverifiedGoogleEmailIsRefused() throws Exception {
        String email = uniqueEmail();
        Map<String, Object> claims = person(email);
        claims.put("email_verified", false);

        assertThat(signIn(claims)).containsEntry("error", "EMAIL_NOT_VERIFIED");
        assertThat(userRepository.findByEmail(email)).isEmpty();
    }

    @Test
    void aListedAdminEmailSignsUpAsAdmin() throws Exception {
        String email = "first-admin@authcore.test"; // auth.admin-emails in application-test.yml
        jdbc.update("delete from users where email = ?", email);

        exchange(signIn(person(email)).get("code")).andExpect(status().isOk());

        assertThat(user(email).getRole().name()).isEqualTo("ADMIN");
    }

    // ---- an account with the same email ----------------------------------------------------

    @Test
    void aVerifiedAccountGetsGoogleLinkedAndIsTold() throws Exception {
        String email = uniqueEmail();
        registerVerifiedUserAndLogin(email);

        ResultActions login = exchange(signIn(person(email)).get("code"));

        getProfile(accessToken(login)).andExpect(jsonPath("$.email").value(email));
        assertThat(htmlBody(awaitEmail(email, LINKED))).contains("Sign in with Google");
        // The password goes on working.
        login(email, PASSWORD).andExpect(status().isOk());
    }

    @Test
    void anUnverifiedAccountIsTakenOverAndItsPasswordStopsWorking() throws Exception {
        String email = uniqueEmail();
        register(email, "Squatter-passw0rd!").andExpect(status().isOk());
        String verificationLink = verificationToken(email);

        ResultActions login = exchange(signIn(person(email)).get("code"));

        getProfile(accessToken(login)).andExpect(jsonPath("$.firstName").value("Jane"));
        // Verified now: "Forgot password" works for it.
        assertThat(user(email).isEnabled()).isTrue();
        requestPasswordReset(email).andExpect(status().isOk());
        passwordResetOtp(email);
        login(email, "Squatter-passw0rd!").andExpect(status().isUnauthorized());
        verifyEmail(verificationLink).andExpect(status().isBadRequest());
        assertNoEmail(email, LINKED);
    }

    @Test
    void anAccountLinkedToAnotherGoogleAccountIsRefused() throws Exception {
        String email = uniqueEmail();
        exchange(signIn(person(email)).get("code")).andExpect(status().isOk());

        // Another Google account that has this email now.
        assertThat(signIn(UUID.randomUUID().toString(), person(email))).containsEntry("error", "OTHER_GOOGLE_ACCOUNT");
    }

    @Test
    void aLockedAccountIsRefused() throws Exception {
        String email = uniqueEmail();
        registerVerifiedUserAndLogin(email);
        jdbc.update("update users set locked_at = now() where email = ?", email);

        assertThat(signIn(person(email))).containsEntry("error", "ACCOUNT_LOCKED");
    }

    @Test
    void anAddressAnEmailChangeCanGoBackToIsRefused() throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);
        String newEmail = uniqueEmail();
        mvc.perform(as(accessToken, post("/api/v1/users/me/email")).contentType(MediaType.APPLICATION_JSON)
                .content("{\"currentPassword\": \"%s\", \"newEmail\": \"%s\"}".formatted(PASSWORD, newEmail)));
        mvc.perform(as(accessToken, post("/api/v1/users/me/email/confirm")).contentType(MediaType.APPLICATION_JSON)
                .content("{\"otp\": \"%s\"}".formatted(emailChangeOtp(newEmail)))).andExpect(status().isOk());

        assertThat(signIn(person(email))).containsEntry("error", "EMAIL_UNAVAILABLE");
    }

    // ---- two-factor authentication -----------------------------------------------------------

    @Test
    void withTwoFactorTheExchangeOnlyGetsAChallenge() throws Exception {
        String email = uniqueEmail();
        String accessToken = registerVerifiedUserAndLogin(email);
        String setup = mvc.perform(as(accessToken, post("/api/v1/users/me/2fa/setup"))
                .contentType(MediaType.APPLICATION_JSON).content("{\"currentPassword\": \"%s\"}".formatted(PASSWORD)))
                .andReturn().getResponse().getContentAsString();
        byte[] secret = Totp.fromBase32(JsonPath.read(setup, "$.secret"));
        mvc.perform(as(accessToken, post("/api/v1/users/me/2fa/enable")).contentType(MediaType.APPLICATION_JSON)
                .content("{\"code\": \"%s\"}".formatted(Totp.code(secret, Totp.step(Instant.now())))))
                .andExpect(status().isOk());

        ResultActions first = exchange(signIn(person(email)).get("code"))
                .andExpect(jsonPath("$.secondFactorRequired").value(true))
                .andExpect(jsonPath("$.accessToken").doesNotExist());

        String challenge = JsonPath.read(first.andReturn().getResponse().getContentAsString(), "$.challenge");
        postJson("/api/v1/auth/login/2fa", "{\"challenge\": \"%s\", \"code\": \"%s\"}"
                .formatted(challenge, Totp.code(secret, Totp.step(Instant.now()) + 1)))
                .andExpect(status().isOk()).andExpect(jsonPath("$.accessToken").isNotEmpty());
    }

    // ---- the code and the request cookie -----------------------------------------------------

    @Test
    void theCodeWorksOnceAndNotAfterAMinute() throws Exception {
        String email = uniqueEmail();
        String code = signIn(person(email)).get("code");

        exchange(code).andExpect(status().isOk());
        exchange(code).andExpect(status().isBadRequest()).andExpect(jsonPath("$.code").value("INVALID_CODE"));

        String late = signIn(person(email)).get("code");
        jdbc.update("update one_time_tokens set expires_at = now(6) - interval 1 second where purpose = 'SOCIAL_LOGIN'"
                + " and user_id = ?", user(email).getId());
        exchange(late).andExpect(status().isBadRequest());
        exchange("made-up").andExpect(status().isBadRequest());
    }

    @Test
    void theRequestCookieIsEncryptedHttpOnlyLaxAndShortLived() throws Exception {
        MockHttpServletResponse start = mvc.perform(get("/api/v1/auth/oauth2/authorization/google"))
                .andExpect(status().isFound()).andReturn().getResponse();

        String header = start.getHeaders(HttpHeaders.SET_COOKIE).stream()
                .filter(cookie -> cookie.startsWith("oauth2Request=")).findFirst().orElseThrow();
        assertThat(header).contains("HttpOnly", "SameSite=Lax", "Path=/api/v1/auth/oauth2", "Max-Age=300");
        String location = start.getRedirectedUrl();
        assertThat(location).contains("code_challenge=", "code_challenge_method=S256", "nonce=", "state=");
        String state = query(location).get("state");
        assertThat(header).doesNotContain(state);
    }

    @Test
    void aChangedCookieOrAnotherStateFails() throws Exception {
        MockHttpServletResponse start = mvc.perform(get("/api/v1/auth/oauth2/authorization/google")).andReturn()
                .getResponse();
        Cookie cookie = start.getCookie("oauth2Request");
        Map<String, String> back = query(signInAtProvider(start.getRedirectedUrl(), UUID.randomUUID().toString(),
                person(uniqueEmail())));
        String value = cookie.getValue();
        Cookie changed = new Cookie("oauth2Request", value.substring(0, value.length() - 2)
                + (value.endsWith("AA") ? "BB" : "AA"));

        assertThat(callback(back.get("code"), back.get("state"), changed)).containsEntry("error", "GOOGLE_SIGN_IN_FAILED");
        assertThat(callback(back.get("code"), "another-state", cookie)).containsEntry("error", "GOOGLE_SIGN_IN_FAILED");
    }

    @Test
    void cancellingAtGoogleSendsTheBrowserBackWithAnError() throws Exception {
        MockHttpServletResponse start = mvc.perform(get("/api/v1/auth/oauth2/authorization/google")).andReturn()
                .getResponse();
        String state = query(start.getRedirectedUrl()).get("state");

        MockHttpServletResponse back = mvc.perform(get("/api/v1/auth/oauth2/callback/google")
                .param("error", "access_denied").param("state", state).cookie(start.getCookie("oauth2Request")))
                .andReturn().getResponse();

        assertThat(back.getRedirectedUrl()).isEqualTo(FRONTEND_PAGE + "error=GOOGLE_SIGN_IN_FAILED");
    }

    @Test
    void signInsAreAuditedWithoutAddressesOrCodes(CapturedOutput output) throws Exception {
        String email = uniqueEmail();
        String linkedEmail = uniqueEmail();
        registerVerifiedUserAndLogin(linkedEmail);
        String code = signIn(person(email)).get("code");
        exchange(code).andExpect(status().isOk());
        exchange(signIn(person(linkedEmail)).get("code")).andExpect(status().isOk());
        Map<String, Object> unverified = person(uniqueEmail());
        unverified.put("email_verified", false);
        signIn(unverified);

        List<String> audit = output.getAll().lines().filter(line -> line.contains(" AUDIT ")).toList();
        assertThat(audit).anyMatch(line -> line.contains("GOOGLE_SIGN_UP userId=" + user(email).getId()));
        assertThat(audit).anyMatch(line -> line.contains("GOOGLE_LINKED userId=" + user(linkedEmail).getId()));
        assertThat(audit).anyMatch(line -> line.contains("LOGIN_SUCCEEDED userId=" + user(email).getId())
                && line.contains("via=GOOGLE"));
        assertThat(audit).anyMatch(line -> line.contains("LOGIN_FAILED") && line.contains("reason=EMAIL_NOT_VERIFIED"));
        assertThat(audit).noneMatch(line -> line.contains(email) || line.contains(linkedEmail) || line.contains(code));
    }

    // ---- helpers ---------------------------------------------------------------------------------

    private static Map<String, Object> person(String email) {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("email", email);
        claims.put("email_verified", true);
        claims.put("given_name", "Jane");
        claims.put("family_name", "Doe");
        return claims;
    }

    private Map<String, String> signIn(Map<String, Object> claims) throws Exception {
        return signIn(UUID.randomUUID().toString(), claims);
    }

    /** The whole way: start, sign in at the provider, back to the callback. */
    private Map<String, String> signIn(String subject, Map<String, Object> claims) throws Exception {
        MockHttpServletResponse start = mvc.perform(get("/api/v1/auth/oauth2/authorization/google"))
                .andExpect(status().isFound()).andReturn().getResponse();
        Map<String, String> back = query(signInAtProvider(start.getRedirectedUrl(), subject, claims));
        return callback(back.get("code"), back.get("state"), start.getCookie("oauth2Request"));
    }

    /** Fills in the provider's login form; returns where it sends the browser back to. */
    private String signInAtProvider(String authorizeUrl, String subject, Map<String, Object> claims) throws Exception {
        String claimsJson = new tools.jackson.databind.json.JsonMapper().writeValueAsString(claims);
        String form = "username=" + encode(subject) + "&claims=" + encode(claimsJson);
        HttpResponse<String> answer = http.send(HttpRequest.newBuilder(URI.create(authorizeUrl))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(form)).build(), HttpResponse.BodyHandlers.ofString());
        assertThat(answer.statusCode()).as(answer.body()).isEqualTo(302);
        return answer.headers().firstValue("Location").orElseThrow();
    }

    /** @return what the web app's page gets in the fragment: "code" or "error" */
    private Map<String, String> callback(String code, String state, Cookie requestCookie) throws Exception {
        MockHttpServletResponse back = mvc.perform(get("/api/v1/auth/oauth2/callback/google")
                .param("code", code).param("state", state).cookie(requestCookie))
                .andExpect(status().isFound()).andReturn().getResponse();
        String location = back.getRedirectedUrl();
        assertThat(location).startsWith(FRONTEND_PAGE);
        String[] fragment = location.substring(FRONTEND_PAGE.length()).split("=", 2);
        return Map.of(fragment[0], fragment[1]);
    }

    private ResultActions exchange(String code) throws Exception {
        return postJson("/api/v1/auth/oauth2/exchange", "{\"code\": \"%s\"}".formatted(code));
    }

    private static Map<String, String> query(String url) {
        Map<String, String> parameters = new LinkedHashMap<>();
        Matcher matcher = Pattern.compile("[?&]([^=&#]+)=([^&#]*)").matcher(url);
        while (matcher.find())
            parameters.put(matcher.group(1), java.net.URLDecoder.decode(matcher.group(2), StandardCharsets.UTF_8));
        return parameters;
    }

    private static String encode(String text) {
        return URLEncoder.encode(text, StandardCharsets.UTF_8);
    }

    private void assertNoEmail(String to, String subject) throws Exception {
        Thread.sleep(700);
        assertThat(sentEmails(to, subject)).isEmpty();
    }
}
