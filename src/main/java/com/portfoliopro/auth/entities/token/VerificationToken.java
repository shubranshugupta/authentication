package com.portfoliopro.auth.entities.token;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;

@Entity
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "verification_tokens")
public class VerificationToken extends Token {
    @Column(name = "token", nullable = false, length = 1000)
    private String verifyToken;

    @Override
    public String getToken() {
        return verifyToken;
    }

    @Override
    public void setToken(String token) {
        this.verifyToken = token;
    }

    @Override
    public boolean equals(Token obj) {
        if (obj instanceof VerificationToken) {
            return this.verifyToken.equals(obj.getToken()) && this.getId().equals(obj.getId());
        }

        return false;
    }
}
