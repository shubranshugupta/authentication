package com.authcore.auth.token;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.authcore.auth.user.User;

public interface DeleteAccountRepository extends JpaRepository<DeleteAccountOtp, Integer> {
    Optional<DeleteAccountOtp> findByUser(User user);
}
