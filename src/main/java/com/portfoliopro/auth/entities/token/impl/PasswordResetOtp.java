package com.portfoliopro.auth.entities.token.impl;

import com.portfoliopro.auth.entities.token.Token;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;

@Entity
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "password_reset_otp")
public class PasswordResetOtp extends Token {
    @Column(name = "otp", nullable = false)
    private long otp;

    @Override
    public String getToken() {
        return String.valueOf(otp);
    }

    @Override
    public void setToken(String token) {
        this.otp = Long.parseLong(token);
    }

    @Override
    public boolean equals(Token obj) {
        if (obj instanceof PasswordResetOtp) {
            return this.otp == Long.parseLong(obj.getToken()) && this.getId().equals(obj.getId());
        }

        return false;
    }
}
