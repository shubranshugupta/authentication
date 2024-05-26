package com.portfoliopro.auth.entities;

import java.io.Serializable;
import java.sql.Date;
import java.time.Instant;

import org.hibernate.annotations.CreationTimestamp;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Entity
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "refresh_tokens")
public class RefreshToken implements Serializable {
    @Id
    @GeneratedValue
    private Integer id;

    @Column(name = "token", nullable = false, length = 1000)
    private String refreshToken;

    @CreationTimestamp
    @Column(name = "created_at", updatable = false, nullable = false)
    private Date createdAt;

    @Column(name = "expiry_date", nullable = false)
    private Instant expiryDate;

    @OneToOne
    private User user;
}
