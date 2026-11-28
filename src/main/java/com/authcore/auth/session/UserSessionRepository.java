package com.authcore.auth.session;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import com.authcore.auth.user.User;

// Refresh tokens are deleted with their session by the database (V6).
public interface UserSessionRepository extends JpaRepository<UserSession, Long> {
    /** The user of a session that hasn't ended. */
    @Query("""
            select u from UserSession s join User u on u.id = s.userId
            where s.id = :sessionId and u.id = :userId and s.expiresAt > :now""")
    Optional<User> findUserOfActiveSession(Long sessionId, Integer userId, Instant now);

    List<UserSession> findByUserIdAndExpiresAtAfterOrderByLastUsedAtDescIdDesc(Integer userId, Instant now);

    @Modifying
    @Query("delete from UserSession s where s.id = :id")
    void end(Long id);

    @Modifying
    @Query("delete from UserSession s where s.userId = :userId")
    void endAll(Integer userId);

    @Modifying
    @Query("delete from UserSession s where s.userId = :userId and s.id <> :keptId")
    void endAllExcept(Integer userId, Long keptId);

    @Modifying
    @Query("delete from UserSession s where s.userId = :userId and s.expiresAt <= :now")
    void deleteExpired(Integer userId, Instant now);

    // ---- cleanup (SessionCleanup) ----

    @Query("select distinct s.userId from UserSession s where s.expiresAt <= :now")
    List<Integer> findUsersWithExpiredSessions(Instant now, Pageable page);

    /** Their refresh tokens go too (on delete cascade). */
    @Modifying
    @Query("delete from UserSession s where s.userId in :userIds and s.expiresAt <= :now")
    int deleteExpired(Collection<Integer> userIds, Instant now);
}
