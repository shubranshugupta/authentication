package com.portfoliopro.auth.service;

import java.time.Instant;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.portfoliopro.auth.entities.RefreshToken;
import com.portfoliopro.auth.entities.User;
import com.portfoliopro.auth.exception.InvalidTokenException;
import com.portfoliopro.auth.exception.TokenExpireException;
import com.portfoliopro.auth.repository.RefereshTokenRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class RefereshTokenService {
    private final RefereshTokenRepository refereshTokenRepository;
    private final UserService userService;

    @Value("${auth.token.refresh-expiration}")
    private long expireTime;

    public RefreshToken createRefereshToken(String email) {
        User user = userService.getUserByEmail(email);
        if (user == null)
            throw new UsernameNotFoundException(email + " user not exists.");

        RefreshToken refereshToken = refereshTokenRepository.findByUser(user).orElse(null);
        if (refereshToken == null) {
            refereshToken = RefreshToken.builder()
                    .refreshToken(UUID.randomUUID().toString())
                    .expiryDate(Instant.now().plusMillis(expireTime))
                    .user(user)
                    .build();

            refereshToken = refereshTokenRepository.save(refereshToken);
        }

        return refereshToken;
    }

    public RefreshToken verifyRefereshToken(String token) {
        RefreshToken refereshToken = refereshTokenRepository.findByRefreshToken(token)
                .orElseThrow(() -> new InvalidTokenException(token + " is invalid refresh token.",
                        new Throwable("Invalid refresh token")));

        if (refereshToken.getExpiryDate().isBefore(Instant.now())) {
            refereshTokenRepository.delete(refereshToken);
            throw new TokenExpireException(token + " Refresh token is expired",
                    new Throwable("Refresh token is expired"));
        }

        return refereshToken;
    }
}
