package com.authcore.auth.token;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

public interface OneTimeTokenRepository extends JpaRepository<OneTimeToken, Long> {
    Optional<OneTimeToken> findByUserIdAndPurpose(Integer userId, TokenPurpose purpose);

    /** Only the id: the token itself must be read after its user was locked. */
    @Query("select t.userId from OneTimeToken t where t.tokenHash = :tokenHash and t.purpose = :purpose")
    Optional<Integer> findUserId(String tokenHash, TokenPurpose purpose);

    @Query("select count(t) > 0 from OneTimeToken t where t.email = :email and t.purpose = :purpose"
            + " and t.consumedAt is null and t.expiresAt > :now")
    boolean existsUnused(String email, TokenPurpose purpose, Instant now);

    @Modifying
    @Query("delete from OneTimeToken t where t.userId = :userId and t.purpose in :purposes")
    void deleteByUserIdAndPurposeIn(Integer userId, Collection<TokenPurpose> purposes);

    // ---- cleanup (TokenCleanup) ----

    @Query("select distinct t.userId from OneTimeToken t where t.expiresAt <= :now")
    List<Integer> findUsersWithExpiredTokens(Instant now, Pageable page);

    @Modifying
    @Query("delete from OneTimeToken t where t.userId in :userIds and t.expiresAt <= :now")
    int deleteExpired(Collection<Integer> userIds, Instant now);
}
