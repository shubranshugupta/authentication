package com.portfoliopro.auth.entities.token;

import java.sql.Date;
import java.time.Instant;

import lombok.Getter;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.Setter;

import org.hibernate.annotations.CreationTimestamp;

import com.portfoliopro.auth.entities.User;

import jakarta.persistence.Column;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.MappedSuperclass;
import jakarta.persistence.OneToOne;

@Getter
@Setter
// @Entity
@NoArgsConstructor
@AllArgsConstructor
@MappedSuperclass
public abstract class Token {
    @Id
    @GeneratedValue
    private Integer id;

    @CreationTimestamp
    @Column(name = "created_at", updatable = false, nullable = false)
    private Date createdAt;

    @Column(name = "expiry_date", nullable = false)
    private Instant expiryDate;

    @OneToOne
    private User user;

    public abstract String getToken();

    public abstract void setToken(String token);

    public abstract boolean equals(Token obj);
}
