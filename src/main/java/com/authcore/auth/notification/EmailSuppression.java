package com.authcore.auth.notification;

import java.time.Instant;

import org.jspecify.annotations.Nullable;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

/** An address that bounced for good, or whose owner complained: it isn't emailed any more. */
@Entity
@Table(name = "email_suppressions")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class EmailSuppression {
    public enum Reason {
        BOUNCE, COMPLAINT
    }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "email", nullable = false, updatable = false)
    private String email;

    @Enumerated(EnumType.STRING)
    @Column(name = "reason", nullable = false, updatable = false, length = 16)
    private Reason reason;

    /** SES's bounce subtype or complaint type, e.g. "General" or "abuse". */
    @Column(name = "detail", updatable = false, length = 64)
    private @Nullable String detail;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    EmailSuppression(String email, Reason reason, @Nullable String detail, Instant now) {
        this.email = email;
        this.reason = reason;
        this.detail = detail;
        this.createdAt = now;
    }
}
