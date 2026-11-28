package com.authcore.auth.notification;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import com.authcore.auth.common.AuthConfigProperties;
import com.authcore.auth.session.ClientInfo;
import com.authcore.auth.user.User;
import com.authcore.auth.user.UserRepository;

import lombok.RequiredArgsConstructor;

/**
 * Emails the owner of an account about a {@link SecurityAlert}, with when it happened and
 * from where. Call it after the change was committed, like the audit log.
 */
@Component
@RequiredArgsConstructor
public class SecurityNotifier {
    static final String TEMPLATE = "security_alert_email";
    private static final DateTimeFormatter WHEN = DateTimeFormatter
            .ofPattern("d MMMM yyyy, HH:mm 'UTC'", Locale.ENGLISH).withZone(ZoneOffset.UTC);

    private final UserRepository userRepository;
    private final ApplicationEventPublisher events;
    private final AuthConfigProperties properties;

    /** Nothing is sent if the account was deleted meanwhile. */
    public void send(Integer userId, SecurityAlert alert, ClientInfo client) {
        userRepository.findById(userId).ifPresent(user -> send(user, alert, client));
    }

    public void send(User user, SecurityAlert alert, ClientInfo client) {
        Map<String, Object> vars = new HashMap<>(); // not Map.of: some values may be null
        vars.put("firstName", StringUtils.capitalize(user.getFirstName()));
        vars.put("lastName", StringUtils.capitalize(user.getLastName()));
        vars.put("heading", alert.heading);
        vars.put("message", alert.message);
        vars.put("advice", alert.advice);
        vars.put("when", WHEN.format(Instant.now()));
        vars.put("ip", client.ip());
        // Whatever the client calls itself: the template escapes it.
        vars.put("device", client.device() == null || client.device().isBlank() ? "Unknown" : client.device());
        vars.put("frontendUrl", properties.getFrontendUrl());
        events.publishEvent(new EmailRequested(user.getEmail(), alert.subject, TEMPLATE, vars));
    }
}
