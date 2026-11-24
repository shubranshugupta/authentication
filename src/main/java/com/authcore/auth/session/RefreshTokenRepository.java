package com.authcore.auth.session;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.authcore.auth.user.User;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Integer> {
    Optional<RefreshToken> findByRefreshToken(String token);

    Optional<RefreshToken> findByUser(User user);
}
