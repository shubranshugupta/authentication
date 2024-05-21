package com.portfoliopro.auth.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.portfoliopro.auth.entities.User;
import com.portfoliopro.auth.entities.token.impl.PasswordResetOtp;

public interface PasswordResetRepository extends JpaRepository<PasswordResetOtp, Integer> {
    Optional<PasswordResetOtp> findByUser(User user);
}
