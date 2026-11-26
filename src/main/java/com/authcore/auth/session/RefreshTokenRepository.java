package com.authcore.auth.session;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByTokenHash(String tokenHash);

    /** Only the id: the token itself must be read after its user was locked. */
    @Query("select s.userId from RefreshToken t join UserSession s on s.id = t.sessionId where t.tokenHash = :tokenHash")
    Optional<Integer> findUserId(String tokenHash);
}
