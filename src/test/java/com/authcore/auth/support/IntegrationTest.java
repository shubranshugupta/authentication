package com.authcore.auth.support;

import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.BeforeEach;
import org.mockito.Mockito;
import org.mockito.invocation.Invocation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import com.authcore.auth.token.TokenPurpose;
import com.authcore.auth.user.User;
import com.authcore.auth.user.UserRepository;
import com.jayway.jsonpath.JsonPath;

import jakarta.mail.Message;
import jakarta.mail.Multipart;
import jakarta.mail.Part;
import jakarta.mail.Session;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import jakarta.servlet.http.Cookie;

/**
 * Base class for the integration tests: the whole application against real MySQL and
 * Redis (Testcontainers), called over HTTP through MockMvc.
 *
 * <p>Every subclass shares one Spring context, so the containers start once per run.
 * {@link JavaMailSender} is a mock: emails are captured, never sent. Tests read links and
 * codes from those emails, like a user would; the database only has hashes of them.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Import(TestcontainersConfiguration.class)
public abstract class IntegrationTest {
    protected static final String PASSWORD = "Str0ng-Passw0rd!";

    private static final long EMAIL_WAIT_MILLIS = 10_000;

    @Autowired
    protected MockMvc mvc;

    @Autowired
    protected UserRepository userRepository;

    @Autowired
    protected JdbcTemplate jdbc;

    @MockitoBean
    protected JavaMailSender mailSender;

    @BeforeEach
    void stubMailSender() {
        when(mailSender.createMimeMessage()).thenAnswer(invocation -> new MimeMessage((Session) null));
    }

    // ---- users ---------------------------------------------------------------------

    protected static String uniqueEmail() {
        return "user-" + UUID.randomUUID() + "@example.com";
    }

    protected User user(String email) {
        return userRepository.findByEmail(email).orElseThrow();
    }

    /** Registers a user, confirms the email, and returns an access token. */
    protected String registerVerifiedUserAndLogin(String email) throws Exception {
        register(email, PASSWORD).andExpect(status().isOk());
        verifyEmail(verificationToken(email)).andExpect(status().isOk());
        return accessToken(email, PASSWORD);
    }

    // ---- endpoints -----------------------------------------------------------------

    protected ResultActions postJson(String path, String body) throws Exception {
        return mvc.perform(post(path).contentType(MediaType.APPLICATION_JSON).content(body));
    }

    protected ResultActions register(String email, String password) throws Exception {
        return postJson("/api/v1/auth/register", """
                {"firstName": "jane", "lastName": "doe", "email": "%s", "password": "%s"}
                """.formatted(email, password));
    }

    protected ResultActions resendVerification(String email) throws Exception {
        return postJson("/api/v1/auth/email-verification", """
                {"email": "%s"}
                """.formatted(email));
    }

    protected ResultActions verifyEmail(String token) throws Exception {
        return postJson("/api/v1/auth/email-verification/confirm", """
                {"token": "%s"}
                """.formatted(token));
    }

    protected ResultActions requestPasswordReset(String email) throws Exception {
        return postJson("/api/v1/auth/password-reset", """
                {"email": "%s"}
                """.formatted(email));
    }

    protected ResultActions confirmPasswordReset(String email, String otp, String newPassword) throws Exception {
        return postJson("/api/v1/auth/password-reset/confirm", """
                {"email": "%s", "otp": "%s", "password": "%s"}
                """.formatted(email, otp, newPassword));
    }

    protected ResultActions login(String email, String password) throws Exception {
        return postJson("/api/v1/auth/login", """
                {"email": "%s", "password": "%s"}
                """.formatted(email, password));
    }

    protected ResultActions refresh(Cookie refreshCookie) throws Exception {
        return mvc.perform(post("/api/v1/auth/refresh").cookie(refreshCookie));
    }

    protected String accessToken(String email, String password) throws Exception {
        String body = login(email, password)
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return JsonPath.read(body, "$.accessToken");
    }

    protected Cookie refreshCookie(String email, String password) throws Exception {
        Cookie cookie = login(email, password)
                .andExpect(status().isOk())
                .andReturn().getResponse().getCookie("refreshToken");
        if (cookie == null)
            fail("login did not set a refreshToken cookie");
        return cookie;
    }

    protected ResultActions getProfile(String accessToken) throws Exception {
        return mvc.perform(as(accessToken, get("/api/v1/users/me")));
    }

    protected ResultActions updateProfile(String accessToken, String body) throws Exception {
        return mvc.perform(as(accessToken, patch("/api/v1/users/me")).contentType(MediaType.APPLICATION_JSON).content(body));
    }

    protected ResultActions requestAccountDeletion(String accessToken) throws Exception {
        return mvc.perform(as(accessToken, post("/api/v1/users/me/deletion")));
    }

    protected ResultActions confirmAccountDeletion(String accessToken, String otp, String password) throws Exception {
        return mvc.perform(as(accessToken, post("/api/v1/users/me/deletion/confirm"))
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"otp": "%s", "password": "%s"}
                        """.formatted(otp, password)));
    }

    protected static MockHttpServletRequestBuilder as(String accessToken, MockHttpServletRequestBuilder request) {
        return request.header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken);
    }

    // ---- tokens --------------------------------------------------------------------

    private static final Pattern LINK_TOKEN = Pattern.compile("token=([A-Za-z0-9_-]{43})");
    private static final Pattern CODE = Pattern.compile(">(\\d{8})<");

    /** The token in the latest verification link that was sent. */
    protected String verificationToken(String email) throws Exception {
        return find(LINK_TOKEN, htmlBody(awaitEmail(email, "Verify Email")));
    }

    protected String passwordResetOtp(String email) throws Exception {
        return find(CODE, htmlBody(awaitEmail(email, "Password Reset")));
    }

    protected String deleteAccountOtp(String email) throws Exception {
        return find(CODE, htmlBody(awaitEmail(email, "Delete Account")));
    }

    private static String find(Pattern pattern, String html) {
        Matcher matcher = pattern.matcher(html);
        if (!matcher.find())
            fail("The email has no " + pattern);
        return matcher.group(1);
    }

    /** As if the last code had been sent a while ago, so that another one can be sent. */
    protected void waitOutTheCooldown(String email, TokenPurpose purpose) {
        jdbc.update("update one_time_tokens set issued_at = issued_at - interval 61 second"
                + " where user_id = ? and purpose = ?", user(email).getId(), purpose.name());
    }

    /** A code that is guaranteed not to be {@code realOtp}. */
    protected static String wrongOtp(String realOtp) {
        return "12345678".equals(realOtp) ? "87654321" : "12345678";
    }

    // ---- emails --------------------------------------------------------------------

    /**
     * Waits for an email with this subject to be sent to this address, and returns the
     * latest one. Emails are sent on a background thread ({@code @Async}), so they can
     * arrive after the response.
     */
    protected MimeMessage awaitEmail(String to, String subject) throws Exception {
        return awaitEmails(to, subject, 1).getLast();
    }

    /** Waits until this many emails were sent, oldest first. */
    protected List<MimeMessage> awaitEmails(String to, String subject, int count) throws Exception {
        long deadline = System.currentTimeMillis() + EMAIL_WAIT_MILLIS;
        while (System.currentTimeMillis() < deadline) {
            List<MimeMessage> messages = sentEmails(to, subject);
            if (messages.size() >= count)
                return messages;
            Thread.sleep(50);
        }
        return fail("Fewer than " + count + " emails with subject '" + subject + "' were sent to " + to);
    }

    /** The emails with this subject sent to this address so far, oldest first. */
    protected List<MimeMessage> sentEmails(String to, String subject) throws Exception {
        List<MimeMessage> messages = new ArrayList<>();
        for (Invocation invocation : Mockito.mockingDetails(mailSender).getInvocations()) {
            if (invocation.getMethod().getName().equals("send")
                    && invocation.getArguments().length == 1
                    && invocation.getArguments()[0] instanceof MimeMessage message
                    && to.equals(recipient(message))
                    && subject.equals(message.getSubject())) {
                messages.add(message);
            }
        }
        return messages;
    }

    protected static String htmlBody(MimeMessage message) throws Exception {
        String html = findHtml(message);
        if (html == null)
            fail("The email has no HTML part");
        return html;
    }

    private static String findHtml(Part part) throws Exception {
        Object content = part.getContent();
        if (content instanceof String text && part.getDataHandler().getContentType().startsWith("text/html"))
            return text;
        if (content instanceof Multipart multipart) {
            for (int i = 0; i < multipart.getCount(); i++) {
                String html = findHtml(multipart.getBodyPart(i));
                if (html != null)
                    return html;
            }
        }
        return null;
    }

    private static String recipient(MimeMessage message) throws Exception {
        var recipients = message.getRecipients(Message.RecipientType.TO);
        return recipients == null || recipients.length == 0 ? null : ((InternetAddress) recipients[0]).getAddress();
    }
}
