package com.authcore.auth.token;

import static java.nio.charset.StandardCharsets.US_ASCII;

import java.security.MessageDigest;
import java.time.Instant;

import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
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

/**
 * The latest code or link a user was sent for one purpose. There is one row per user and
 * purpose: a new code replaces the old one, and a used one stays until then, so that the
 * resend cooldown still applies. Only a hash is stored, never the code itself.
 */
@Entity
@Table(name = "one_time_tokens")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class OneTimeToken {
    /** Wrong guesses after which a code stops working, even for the right guess (C1). */
    static final int MAX_ATTEMPTS = 5;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_id", nullable = false, updatable = false)
    private Integer userId;

    // varchar, not the MySQL enum Hibernate would expect: a new purpose needs no migration.
    @Enumerated(EnumType.STRING)
    @JdbcTypeCode(SqlTypes.VARCHAR)
    @Column(name = "purpose", nullable = false, updatable = false, length = 32)
    private TokenPurpose purpose;

    @Column(name = "token_hash", nullable = false, length = 64)
    private String tokenHash;

    @Column(name = "attempts", nullable = false)
    private int attempts;

    @Column(name = "issued_at", nullable = false)
    private Instant issuedAt;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "consumed_at")
    private @Nullable Instant consumedAt;

    /**
     * The address this is for, if not the account's: where it was sent, and what the account's
     * email becomes once it's used (the new address, or the old one for an undo link).
     */
    @Column(name = "email")
    private @Nullable String email;

    OneTimeToken(Integer userId, TokenPurpose purpose) {
        this.userId = userId;
        this.purpose = purpose;
    }

    /** Makes this the new, unused token. The old one stops working. */
    void issue(String tokenHash, @Nullable String email, Instant now) {
        this.tokenHash = tokenHash;
        this.email = email;
        this.attempts = 0;
        this.issuedAt = now;
        this.expiresAt = now.plus(purpose.validFor);
        this.consumedAt = null;
    }

    boolean isUsable(Instant now) {
        return consumedAt == null && attempts < MAX_ATTEMPTS && now.isBefore(expiresAt);
    }

    boolean hasHash(String hash) {
        // Takes the same time wherever the first difference is.
        return MessageDigest.isEqual(tokenHash.getBytes(US_ASCII), hash.getBytes(US_ASCII));
    }

    void countWrongAttempt() {
        attempts++;
    }

    void consume(Instant now) {
        consumedAt = now;
    }
}
