package com.portfoliopro.auth.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.portfoliopro.auth.entities.User;
import com.portfoliopro.auth.entities.token.impl.VerificationToken;

public interface VerificationTokenRepository extends JpaRepository<VerificationToken, Integer> {
    Optional<VerificationToken> findByUser(User user);
}
