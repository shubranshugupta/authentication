package com.authcore.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.transaction.support.TransactionTemplate;

import com.authcore.auth.notification.EmailRequested;
import com.authcore.auth.support.IntegrationTest;

import jakarta.mail.internet.MimeMessage;

/** A3: one event and one listener send every email. */
class EmailListenerTests extends IntegrationTest {
    private static final int EMAILS = 200;

    @Autowired
    private ApplicationEventPublisher events;

    @Autowired
    private TransactionTemplate transaction;

    /**
     * C4: the template name used to be a field shared by every request, so overlapping
     * requests sent each other's email (about 1 in 40 in this test).
     */
    @Test
    void emailsRequestedAtTheSameMomentDoNotGetMixedUp() throws Exception {
        String run = UUID.randomUUID() + "@example.com";
        List<Callable<Object>> requests = new ArrayList<>();
        requests.add(() -> {
            for (int i = 0; i < EMAILS; i++)
                events.publishEvent(email("reset-" + i + "-" + run, "Password Reset", "password_reset_email", "code-" + i));
            return null;
        });
        requests.add(() -> {
            for (int i = 0; i < EMAILS; i++)
                events.publishEvent(email("verify-" + i + "-" + run, "Verify Email", "verify_registration_email", "link-" + i));
            return null;
        });

        try (ExecutorService threads = Executors.newFixedThreadPool(2)) {
            for (Future<Object> request : threads.invokeAll(requests))
                request.get();
        }

        for (int i = 0; i < EMAILS; i++) {
            assertThat(htmlBody(awaitEmail("reset-" + i + "-" + run, "Password Reset")))
                    .contains("OTP for password reset is").contains("code-" + i + "<");
            assertThat(htmlBody(awaitEmail("verify-" + i + "-" + run, "Verify Email")))
                    .contains("Thank you for registering").contains("link-" + i + "<");
        }
    }

    @Test
    void emailsAreSentOnTheEmailThreads() throws Exception {
        List<String> threads = new CopyOnWriteArrayList<>();
        Mockito.doAnswer(call -> threads.add(Thread.currentThread().getName()))
                .when(mailSender).send(any(MimeMessage.class));
        String to = uniqueEmail();

        events.publishEvent(email(to, "Password Reset", "password_reset_email", "123456"));
        awaitEmail(to, "Password Reset");

        assertThat(threads).allMatch(name -> name.startsWith("email-"));
    }

    @Test
    void anEmailRequestedInATransactionIsSentWhenItCommits() throws Exception {
        String to = uniqueEmail();

        transaction.execute(status -> {
            events.publishEvent(email(to, "Password Reset", "password_reset_email", "123456"));
            assertNotSentWithin(300, to);
            return null;
        });

        awaitEmail(to, "Password Reset");
    }

    /** Otherwise a user could get a code that was never saved. */
    @Test
    void anEmailRequestedInATransactionThatRollsBackIsNotSent() {
        String to = uniqueEmail();

        transaction.execute(status -> {
            events.publishEvent(email(to, "Password Reset", "password_reset_email", "123456"));
            status.setRollbackOnly();
            return null;
        });

        assertNotSentWithin(500, to);
    }

    @Test
    void theEventDoesNotPrintItsToken() {
        assertThat(email("jane@example.com", "s", "t", "secret-code").toString()).doesNotContain("secret-code");
    }

    private void assertNotSentWithin(long millis, String to) {
        try {
            Thread.sleep(millis);
            assertThat(sentEmail(to, "Password Reset")).isNull();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static EmailRequested email(String to, String subject, String template, String token) {
        return new EmailRequested(to, subject, template,
                Map.of("firstName", "Jane", "lastName", "Doe", "token", token, "baseUrl", "http://localhost"));
    }
}
