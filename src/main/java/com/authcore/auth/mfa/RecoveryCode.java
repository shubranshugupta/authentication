package com.authcore.auth.mfa;

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

/** A code that works instead of the app's once, for a user who lost their phone. Only its hash is stored. */
@Entity
@Table(name = "recovery_codes")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
class RecoveryCode {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_id", nullable = false, updatable = false)
    private Integer userId;

    @Column(name = "code_hash", nullable = false, updatable = false, length = 64)
    private String codeHash;

    @Column(name = "used_at")
    private @Nullable Instant usedAt;

    RecoveryCode(Integer userId, String codeHash) {
        this.userId = userId;
        this.codeHash = codeHash;
    }

    void use(Instant now) {
        this.usedAt = now;
    }
}
