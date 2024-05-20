package com.portfoliopro.auth.entities.token;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;

@Entity
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "otp")
public class Otp extends Token {
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
        if (obj instanceof Otp) {
            return this.otp == Long.parseLong(obj.getToken()) && this.getId().equals(obj.getId());
        }

        return false;
    }
}
