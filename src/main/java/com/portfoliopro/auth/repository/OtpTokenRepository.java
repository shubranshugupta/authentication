package com.portfoliopro.auth.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.portfoliopro.auth.entities.User;
import com.portfoliopro.auth.entities.token.Otp;

public interface OtpTokenRepository extends JpaRepository<Otp, Integer> {
    Optional<Otp> findByUser(User user);
}
