package com.authcore.auth.social;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

interface SocialIdentityRepository extends JpaRepository<SocialIdentity, Long> {
    Optional<SocialIdentity> findByProviderAndSubject(String provider, String subject);

    boolean existsByUserIdAndProvider(Integer userId, String provider);
}
