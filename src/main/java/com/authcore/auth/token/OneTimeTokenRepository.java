package com.authcore.auth.token;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface OneTimeTokenRepository extends JpaRepository<OneTimeToken, Long> {
    Optional<OneTimeToken> findByUserIdAndPurpose(Integer userId, TokenPurpose purpose);

    /** Only the id: the token itself must be read after its user was locked. */
    @Query("select t.userId from OneTimeToken t where t.tokenHash = :tokenHash and t.purpose = :purpose")
    Optional<Integer> findUserId(String tokenHash, TokenPurpose purpose);
}
