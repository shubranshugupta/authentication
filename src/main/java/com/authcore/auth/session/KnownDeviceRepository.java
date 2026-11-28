package com.authcore.auth.session;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

interface KnownDeviceRepository extends JpaRepository<KnownDevice, Long> {
    Optional<KnownDevice> findByUserIdAndDeviceHash(Integer userId, String deviceHash);

    boolean existsByUserId(Integer userId);

    // ---- cleanup (SessionCleanup) ----

    @Query("select distinct d.userId from KnownDevice d where d.lastSeenAt <= :before")
    List<Integer> findUsersWithDevicesUnseenSince(Instant before, Pageable page);

    @Modifying
    @Query("delete from KnownDevice d where d.userId in :userIds and d.lastSeenAt <= :before")
    int deleteUnseenSince(Collection<Integer> userIds, Instant before);
}
