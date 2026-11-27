package com.authcore.auth.mfa;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

interface RecoveryCodeRepository extends JpaRepository<RecoveryCode, Long> {
    Optional<RecoveryCode> findByUserIdAndCodeHashAndUsedAtIsNull(Integer userId, String codeHash);

    int countByUserIdAndUsedAtIsNull(Integer userId);

    @Modifying
    @Query("delete from RecoveryCode c where c.userId = :userId")
    void deleteByUserId(Integer userId);
}
