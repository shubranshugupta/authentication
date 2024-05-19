package com.portfoliopro.auth.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.portfoliopro.auth.entities.User;
import com.portfoliopro.auth.entities.token.Token;

public interface TokenRepository<T extends Token> extends JpaRepository<T, Integer> {
    Optional<T> findByUser(User user);
}
