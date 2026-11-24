package com.authcore.auth.entities;

import java.sql.Date;
import java.util.Arrays;
import java.util.Collection;

import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.authcore.auth.entities.token.impl.DeleteAccountOtp;
import com.authcore.auth.entities.token.impl.PasswordResetOtp;
import com.authcore.auth.entities.token.impl.VerificationToken;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import jakarta.validation.constraints.Email;
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
@Table(name = "users")
@JsonIgnoreProperties({ "authorities" })
public class User implements UserDetails {
    @Id
    @GeneratedValue
    @Column(name = "id", updatable = false, nullable = false)
    private Integer id;

    @Column(name = "first_name", nullable = false)
    private String firstName;

    @Column(name = "last_name")
    private String lastName;

    @Column(name = "email", unique = true, nullable = false)
    @Email(message = "Email should be valid")
    private String email;

    @ToString.Exclude
    @Column(name = "password", nullable = false)
    private String password;

    @CreationTimestamp
    @Column(name = "created_at", updatable = false, nullable = false)
    private Date createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private Date updatedAt;

    @Enumerated(EnumType.STRING)
    @Column(name = "role", nullable = false)
    private Role role;

    // Named "enabled", not "isEnabled": Jackson 3 builds a cached User through the
    // all-args constructor, matching parameter names to JSON properties. The getter
    // isEnabled() writes the property as "enabled", so a parameter named "isEnabled"
    // was never matched and reading a cached user failed.
    @Column(name = "is_enabled", nullable = false)
    private boolean enabled;

    @ToString.Exclude
    @JsonIgnore
    @OneToOne(mappedBy = "user", cascade = CascadeType.REMOVE, orphanRemoval = true)
    private RefreshToken refreshToken;

    @ToString.Exclude
    @JsonIgnore
    @OneToOne(mappedBy = "user", cascade = CascadeType.REMOVE, orphanRemoval = true)
    private VerificationToken verificationToken;

    @ToString.Exclude
    @JsonIgnore
    @OneToOne(mappedBy = "user", cascade = CascadeType.REMOVE, orphanRemoval = true)
    private PasswordResetOtp passwordResetOtp;

    @ToString.Exclude
    @JsonIgnore
    @OneToOne(mappedBy = "user", cascade = CascadeType.REMOVE, orphanRemoval = true)
    private DeleteAccountOtp deleteAccountOtp;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // Spring's hasRole('ADMIN') checks for the authority "ROLE_ADMIN".
        return Arrays.asList(new SimpleGrantedAuthority("ROLE_" + role.name()));
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    // JPA entities compare by database id only. Lombok's @Data compared every field,
    // and User <-> RefreshToken point at each other, so equals/hashCode/toString
    // recursed until StackOverflowError. getId() (not the field) works on Hibernate
    // proxies; the constant hashCode stays stable when a new entity gets its id.
    @Override
    public boolean equals(Object other) {
        if (this == other)
            return true;
        if (!(other instanceof User that))
            return false;
        return getId() != null && getId().equals(that.getId());
    }

    @Override
    public int hashCode() {
        return getClass().hashCode();
    }
}
