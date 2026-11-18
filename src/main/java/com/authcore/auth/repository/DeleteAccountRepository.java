package com.authcore.auth.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.authcore.auth.entities.User;
import com.authcore.auth.entities.token.impl.DeleteAccountOtp;

public interface DeleteAccountRepository extends JpaRepository<DeleteAccountOtp, Integer> {
    Optional<DeleteAccountOtp> findByUser(User user);
}
