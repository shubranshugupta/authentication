package com.authcore.auth.session;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

/** A browser or app a user has logged in from (see {@link DeviceService}). */
@Entity
@Table(name = "known_devices")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
class KnownDevice {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_id", nullable = false, updatable = false)
    private Integer userId;

    @Column(name = "device_hash", nullable = false, updatable = false, length = 64)
    private String deviceHash;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "last_seen_at", nullable = false)
    private Instant lastSeenAt;

    KnownDevice(Integer userId, String deviceHash, Instant now) {
        this.userId = userId;
        this.deviceHash = deviceHash;
        this.createdAt = now;
        this.lastSeenAt = now;
    }

    void seen(Instant now) {
        this.lastSeenAt = now;
    }
}
