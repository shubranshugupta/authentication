package com.authcore.auth.mfa;

import java.util.Collection;
import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

interface TotpCredentialRepository extends JpaRepository<TotpCredential, Integer> {
    @Query("select count(c) > 0 from TotpCredential c where c.userId = :userId and c.enabledAt is not null")
    boolean isEnabled(Integer userId);

    @Query("select c.userId from TotpCredential c where c.userId in :userIds and c.enabledAt is not null")
    List<Integer> findEnabled(Collection<Integer> userIds);
}
