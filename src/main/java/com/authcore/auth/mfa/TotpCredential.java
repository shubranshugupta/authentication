package com.authcore.auth.mfa;

import java.time.Duration;
import java.time.Instant;

import org.jspecify.annotations.Nullable;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * A user's authenticator app: the encrypted secret, and the guesses at its codes. Until
 * {@code enabledAt} is set, it's a setup the user hasn't confirmed with a code yet.
 */
@Entity
@Table(name = "totp_credentials")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
class TotpCredential {
    /** Wrong codes in a row after which none is checked for a while. */
    static final int MAX_FAILED_ATTEMPTS = 5;
    static final Duration LOCKOUT = Duration.ofMinutes(15);

    @Id
    @Column(name = "user_id", nullable = false, updatable = false)
    private Integer userId;

    @Column(name = "secret", nullable = false, length = 64)
    private byte[] secret;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "enabled_at")
    private @Nullable Instant enabledAt;

    /** The time step of the last code used: neither it nor an older one works again. */
    @Column(name = "last_used_step", nullable = false)
    private long lastUsedStep;

    @Column(name = "failed_attempts", nullable = false)
    private int failedAttempts;

    @Column(name = "last_failed_at")
    private @Nullable Instant lastFailedAt;

    TotpCredential(Integer userId, byte[] secret, Instant now) {
        this.userId = userId;
        this.secret = secret;
        this.createdAt = now;
    }

    boolean isEnabled() {
        return enabledAt != null;
    }

    void enable(Instant now) {
        this.enabledAt = now;
    }

    /** How long until codes are checked again; zero if they are now. */
    Duration lockedFor(Instant now) {
        if (failedAttempts < MAX_FAILED_ATTEMPTS || lastFailedAt == null)
            return Duration.ZERO;
        Duration left = Duration.between(now, lastFailedAt.plus(LOCKOUT));
        return left.isNegative() ? Duration.ZERO : left;
    }

    void failed(Instant now) {
        // Guesses from long ago don't add up with today's.
        if (lastFailedAt != null && lastFailedAt.plus(LOCKOUT).isBefore(now))
            failedAttempts = 0;
        failedAttempts++;
        lastFailedAt = now;
    }

    void succeeded(long step) {
        lastUsedStep = Math.max(lastUsedStep, step);
        failedAttempts = 0;
        lastFailedAt = null;
    }
}
