package com.authcore.auth.notification;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

interface EmailSuppressionRepository extends JpaRepository<EmailSuppression, Long> {
    boolean existsByEmail(String email);

    @Modifying
    @Query("delete from EmailSuppression s where s.email = :email")
    int deleteByEmail(String email);
}
