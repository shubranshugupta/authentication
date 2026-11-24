package com.authcore.auth.token;

import java.sql.Date;
import java.time.Instant;

import org.hibernate.annotations.CreationTimestamp;

import com.authcore.auth.user.User;

import jakarta.persistence.Column;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.MappedSuperclass;
import jakarta.persistence.OneToOne;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
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
}
