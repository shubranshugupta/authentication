package com.authcore.auth.token;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.authcore.auth.user.User;

public interface PasswordResetRepository extends JpaRepository<PasswordResetOtp, Integer> {
    Optional<PasswordResetOtp> findByUser(User user);
}
