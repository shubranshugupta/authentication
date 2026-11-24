package com.authcore.auth.token;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.authcore.auth.user.User;

public interface VerificationTokenRepository extends JpaRepository<VerificationToken, Integer> {
    Optional<VerificationToken> findByUser(User user);
}
