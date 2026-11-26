package com.authcore.auth.audit;

import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.spi.LoggingEventBuilder;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import com.authcore.auth.session.ClientInfo;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tags;
import lombok.RequiredArgsConstructor;

/**
 * The audit log (F2): one line per security event, such as
 * {@code LOGIN_FAILED userId=12 ip=203.0.113.7 reason=WRONG_PASSWORD}.
 *
 * <p>It has a logger of its own, "AUDIT", so that its lines can be sent elsewhere or kept
 * longer. In JSON logs (prod) every value is a field of its own, next to the trace id.
 * Lines never contain emails, passwords, codes or tokens: only ids, the client's address
 * and short reasons.
 *
 * <p>Each event is also counted, in the metric {@code authcore.audit_events} (with the tags
 * "event" and "reason"), e.g. for an alert on many failed logins.
 */
@Component
@RequiredArgsConstructor
public class AuditLog {
    private static final Logger LOG = LoggerFactory.getLogger("AUDIT");

    private final MeterRegistry meters;

    /**
     * Call it after the change was committed, so that the log never has something that
     * was rolled back.
     *
     * @param userId  the account it's about, null if there is none
     * @param details more names and values, e.g. "reason", "WRONG_PASSWORD"
     */
    public void record(AuditEvent event, @Nullable Integer userId, Object... details) {
        if (details.length % 2 != 0)
            throw new IllegalArgumentException("details are pairs of names and values");
        LoggingEventBuilder line = LOG.atInfo().addKeyValue("event", event.name());
        StringBuilder text = new StringBuilder(event.name());
        add(line, text, "userId", userId);
        add(line, text, "ip", clientIp());
        Tags tags = Tags.of("event", event.name());
        for (int i = 0; i < details.length; i += 2) {
            add(line, text, String.valueOf(details[i]), details[i + 1]);
            if ("reason".equals(details[i]))
                tags = tags.and("reason", String.valueOf(details[i + 1]));
        }
        line.log(text.toString());
        meters.counter("authcore.audit_events", tags).increment();
    }

    private static void add(LoggingEventBuilder line, StringBuilder text, String name, @Nullable Object value) {
        if (value == null)
            return;
        line.addKeyValue(name, value);
        text.append(' ').append(name).append('=').append(value);
    }

    /** The address of the request being handled, if there is one. */
    private static @Nullable String clientIp() {
        return RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes request
                ? ClientInfo.of(request.getRequest()).ip()
                : null;
    }
}
