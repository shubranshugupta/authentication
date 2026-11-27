package com.authcore.auth.support;

import org.mockito.Answers;
import org.mockito.Mockito;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.mail.javamail.JavaMailSender;

import jakarta.mail.Session;
import jakarta.mail.internet.MimeMessage;

/**
 * The integration tests' {@link JavaMailSender}: a mock that captures every email, so tests
 * can read them ({@link IntegrationTest#sentEmails}).
 *
 * <p>Creating a message is part of the mock itself (its default answer), not a stub added
 * before each test: emails are sent on background threads, which go on using the mock while
 * tests start and end. A {@code @MockitoBean} is reset after every test, and an email thread
 * could then, now and then, see the mock without the stub and get no message at all. That
 * made a random test fail every few runs ("Fewer than 1 emails ... were sent"). This mock
 * isn't reset by Spring, and a {@link Mockito#reset} keeps its default answer.
 */
@TestConfiguration(proxyBeanMethods = false)
public class CapturedMailConfiguration {
    @Bean
    JavaMailSender mailSender() {
        return Mockito.mock(JavaMailSender.class, Mockito.withSettings().defaultAnswer(invocation ->
                invocation.getMethod().getName().equals("createMimeMessage") && invocation.getArguments().length == 0
                        ? new MimeMessage((Session) null)
                        : Answers.RETURNS_DEFAULTS.answer(invocation)));
    }
}
