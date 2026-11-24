package com.authcore.auth.entities.token.impl;

import com.authcore.auth.entities.token.Token;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;

@Entity
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "delete_account_otp")
public class DeleteAccountOtp extends Token {
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
}
