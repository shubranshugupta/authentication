package com.authcore.auth.support;

import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.mockito.Mockito;
import org.mockito.invocation.Invocation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import com.authcore.auth.token.DeleteAccountRepository;
import com.authcore.auth.token.PasswordResetRepository;
import com.authcore.auth.token.VerificationTokenRepository;
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
 * {@link JavaMailSender} is a mock: emails are captured, never sent. Tests read tokens
 * and OTPs from the database, and check the email that carried them.
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
    protected VerificationTokenRepository verificationTokenRepository;

    @Autowired
    protected PasswordResetRepository passwordResetRepository;

    @Autowired
    protected DeleteAccountRepository deleteAccountRepository;

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
        verifyEmail(email, verificationToken(email)).andExpect(status().isOk());
        return accessToken(email, PASSWORD);
    }

    // ---- endpoints -----------------------------------------------------------------

    protected ResultActions register(String email, String password) throws Exception {
        return mvc.perform(post("/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"firstName": "jane", "lastName": "doe", "email": "%s", "password": "%s"}
                        """.formatted(email, password)));
    }

    protected ResultActions verifyEmail(String email, String token) throws Exception {
        return mvc.perform(get("/auth/verify-email").param("email", email).param("token", token));
    }

    protected ResultActions login(String email, String password) throws Exception {
        return mvc.perform(post("/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"email": "%s", "password": "%s"}
                        """.formatted(email, password)));
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
        return mvc.perform(get("/user/get-info").header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken));
    }

    // ---- tokens --------------------------------------------------------------------

    protected String verificationToken(String email) {
        return verificationTokenRepository.findByUser(user(email)).orElseThrow().getToken();
    }

    protected String passwordResetOtp(String email) {
        return passwordResetRepository.findByUser(user(email)).orElseThrow().getToken();
    }

    protected String deleteAccountOtp(String email) {
        return deleteAccountRepository.findByUser(user(email)).orElseThrow().getToken();
    }

    /** A 6-digit OTP that is guaranteed not to be {@code realOtp}. */
    protected static String wrongOtp(String realOtp) {
        return "123456".equals(realOtp) ? "654321" : "123456";
    }

    // ---- emails --------------------------------------------------------------------

    /**
     * Waits for an email with this subject to be sent to this address. Emails are sent
     * on a background thread ({@code @Async}), so they can arrive after the response.
     */
    protected MimeMessage awaitEmail(String to, String subject) throws Exception {
        long deadline = System.currentTimeMillis() + EMAIL_WAIT_MILLIS;
        while (System.currentTimeMillis() < deadline) {
            MimeMessage message = sentEmail(to, subject);
            if (message != null)
                return message;
            Thread.sleep(50);
        }
        return fail("No email with subject '" + subject + "' was sent to " + to);
    }

    /** The email with this subject sent to this address so far, or null. */
    protected MimeMessage sentEmail(String to, String subject) throws Exception {
        for (Invocation invocation : Mockito.mockingDetails(mailSender).getInvocations()) {
            if (invocation.getMethod().getName().equals("send")
                    && invocation.getArguments().length == 1
                    && invocation.getArguments()[0] instanceof MimeMessage message
                    && to.equals(recipient(message))
                    && subject.equals(message.getSubject())) {
                return message;
            }
        }
        return null;
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
