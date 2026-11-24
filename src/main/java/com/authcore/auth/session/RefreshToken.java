package com.authcore.auth.session;

import java.sql.Date;
import java.time.Instant;

import org.hibernate.annotations.CreationTimestamp;

import com.authcore.auth.user.User;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
@Entity
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "refresh_tokens")
public class RefreshToken {
    @Id
    @GeneratedValue
    private Integer id;

    @ToString.Exclude
    @Column(name = "token", nullable = false, length = 1000)
    private String refreshToken;

    @CreationTimestamp
    @Column(name = "created_at", updatable = false, nullable = false)
    private Date createdAt;

    @Column(name = "expiry_date", nullable = false)
    private Instant expiryDate;

    @ToString.Exclude
    @OneToOne
    private User user;

    // JPA entities compare by database id only. getId() (not the field) works on Hibernate
    // proxies; the constant hashCode stays stable when a new entity gets its id.
    @Override
    public boolean equals(Object other) {
        if (this == other)
            return true;
        if (!(other instanceof RefreshToken that))
            return false;
        return getId() != null && getId().equals(that.getId());
    }

    @Override
    public int hashCode() {
        return getClass().hashCode();
    }
}
