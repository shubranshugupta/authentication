package com.portfoliopro.auth.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.portfoliopro.auth.entities.User;
import com.portfoliopro.auth.entities.token.DeleteAccountOtp;

public interface DeleteAccountRepository extends JpaRepository<DeleteAccountOtp, Integer> {
    Optional<DeleteAccountOtp> findByUser(User user);
}
