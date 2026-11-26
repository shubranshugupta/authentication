package com.authcore.auth.session;

import java.time.Instant;

import org.jspecify.annotations.Nullable;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * One login on one device. Ending a session means deleting its row: its refresh tokens go
 * with it, and its access tokens stop working.
 */
@Entity
@Table(name = "user_sessions")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class UserSession {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_id", nullable = false, updatable = false)
    private Integer userId;

    @Column(name = "device", length = 255)
    private @Nullable String device;

    @Column(name = "ip", nullable = false, length = 45)
    private String ip;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "last_used_at", nullable = false)
    private Instant lastUsedAt;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    UserSession(Integer userId, Instant now) {
        this.userId = userId;
        this.createdAt = now;
    }

    /** The session was used: it now lasts until {@code expiresAt}. */
    void use(ClientInfo client, Instant now, Instant expiresAt) {
        this.ip = client.ip();
        this.device = client.device();
        this.lastUsedAt = now;
        this.expiresAt = expiresAt;
    }

    boolean isExpired(Instant now) {
        return !now.isBefore(expiresAt);
    }
}
