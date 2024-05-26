package com.portfoliopro.auth.service;

import java.time.Instant;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
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
    private final CacheService<String, RefreshToken> cacheService;

    @Value("${auth.token.refresh-expiration}")
    private long expireTime;

    public RefreshToken createRefereshToken(User user) {
        RefreshToken refereshToken = refereshTokenRepository.findByUser(user).orElse(null);
        if (refereshToken != null && refereshToken.getExpiryDate().isAfter(Instant.now())) {
            return refereshToken;
        }

        if (refereshToken != null) {
            deleteRefreshTokenFromCache(refereshToken.getRefreshToken());
            refereshTokenRepository.delete(refereshToken);
        }

        refereshToken = RefreshToken.builder().refreshToken(UUID.randomUUID().toString())
                .expiryDate(Instant.now().plusMillis(expireTime)).user(user).build();
        refereshToken = refereshTokenRepository.save(refereshToken);
        return refereshToken;
    }

    public RefreshToken verifyRefereshToken(String token) {
        RefreshToken refereshToken = getRefereshTokenFromToken(token);
        if (refereshToken == null) {
            throw new InvalidTokenException(token + " is invalid refresh token.",
                    new Throwable("Invalid refresh token"));
        }

        if (refereshToken.getExpiryDate().isBefore(Instant.now())) {
            deleteRefreshTokenFromCache(token);
            refereshTokenRepository.delete(refereshToken);
            throw new TokenExpireException(token + " Refresh token is expired",
                    new Throwable("Refresh token is expired"));
        }

        return refereshToken;
    }

    private RefreshToken getRefereshTokenFromToken(String token) {
        String cacheTokenKey = buildCacheKey(token);
        if (cacheService.contains(cacheTokenKey)) {
            return cacheService.getValue(cacheTokenKey, RefreshToken.class);
        }

        RefreshToken refereshToken = refereshTokenRepository.findByRefreshToken(token).orElse(null);
        if (refereshToken != null) {
            cacheService.save(cacheTokenKey, refereshToken);
        }
        return refereshToken;
    }

    private void deleteRefreshTokenFromCache(String token) {
        String cacheTokenKey = buildCacheKey(token);
        if (cacheService.contains(cacheTokenKey)) {
            cacheService.delete(cacheTokenKey);
        }
    }

    public String buildCacheKey(String email) {
        return "refreshToken-" + email;
    }
}
