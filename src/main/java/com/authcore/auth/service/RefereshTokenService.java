package com.authcore.auth.service;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.authcore.auth.entities.RefreshToken;
import com.authcore.auth.entities.User;
import com.authcore.auth.exception.InvalidTokenException;
import com.authcore.auth.exception.TokenExpireException;
import com.authcore.auth.repository.RefereshTokenRepository;

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
            refereshTokenRepository.deleteAllByIdInBatch(List.of(refereshToken.getId()));
        }

        refereshToken = RefreshToken.builder().refreshToken(UUID.randomUUID().toString())
                .expiryDate(Instant.now().plusMillis(expireTime)).user(user).build();
        refereshToken = refereshTokenRepository.save(refereshToken);
        return refereshToken;
    }

    public RefreshToken verifyRefereshToken(String token) {
        RefreshToken refereshToken = getRefereshTokenFromToken(token);
        if (refereshToken == null) {
            // Never echo the token: error responses and logs must not contain it (H2).
            throw new InvalidTokenException("Invalid refresh token");
        }

        if (refereshToken.getExpiryDate().isBefore(Instant.now())) {
            refereshTokenRepository.deleteAllByIdInBatch(List.of(refereshToken.getId()));
            throw new TokenExpireException("Refresh token has expired");
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
            cacheService.save(cacheTokenKey, refereshToken, expireTime);
        }
        return refereshToken;
    }

    // private void deleteRefreshTokenFromCache(String token) {
    // String cacheTokenKey = buildCacheKey(token);
    // if (cacheService.contains(cacheTokenKey)) {
    // cacheService.delete(cacheTokenKey);
    // }
    // }

    public String buildCacheKey(String email) {
        return "refreshToken-" + email;
    }
}
