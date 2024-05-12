package com.portfoliopro.auth.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.portfoliopro.auth.entities.Otp;
import com.portfoliopro.auth.entities.User;
import java.util.Optional;

public interface OtpRepository extends JpaRepository<Otp, Integer> {
    Optional<Otp> findByUser(User user);
}
