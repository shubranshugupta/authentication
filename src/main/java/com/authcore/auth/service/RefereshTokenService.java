package com.authcore.auth.service;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;

import com.authcore.auth.utils.DeadlockRetry;
import com.authcore.auth.repository.UserRepository;
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
    private final UserRepository userRepository;
    private final CacheService<String, CachedRefreshToken> cacheService;

    @Value("${auth.token.refresh-expiration}")
    private long expireTime;

    public RefreshToken createRefereshToken(User user) {
        return DeadlockRetry.run(() -> tryToCreateRefereshToken(user));
    }

    private RefreshToken tryToCreateRefereshToken(User user) {
        RefreshToken refereshToken = refereshTokenRepository.findByUser(user).orElse(null);
        if (refereshToken != null && refereshToken.getExpiryDate().isAfter(Instant.now())) {
            return refereshToken;
        }

        if (refereshToken != null) {
            refereshTokenRepository.deleteAllByIdInBatch(List.of(refereshToken.getId()));
        }

        refereshToken = RefreshToken.builder().refreshToken(UUID.randomUUID().toString())
                .expiryDate(Instant.now().plusMillis(expireTime)).user(user).build();
        try {
            return refereshTokenRepository.save(refereshToken);
        } catch (DataIntegrityViolationException e) {
            // Another login of this user created the token at the same moment: share it.
            return refereshTokenRepository.findByUser(user).orElseThrow(() -> e);
        }
    }

    public void deleteRefereshToken(User user) {
        refereshTokenRepository.findByUser(user)
                .ifPresent(token -> refereshTokenRepository.deleteAllByIdInBatch(List.of(token.getId())));
    }

    /** Returns the user this refresh token belongs to. */
    public User verifyRefereshToken(String token) {
        // Never echo the token: error responses and logs must not contain it (H2).
        CachedRefreshToken refereshToken = getRefereshTokenFromToken(token);
        if (refereshToken == null) {
            throw new InvalidTokenException("Invalid refresh token");
        }
        if (refereshToken.expiryDate().isBefore(Instant.now())) {
            refereshTokenRepository.deleteAllByIdInBatch(List.of(refereshToken.tokenId()));
            throw new TokenExpireException("Refresh token has expired");
        }
        // Always from the database: a cached token can outlive its user's account.
        return userRepository.findById(refereshToken.userId())
                .orElseThrow(() -> new InvalidTokenException("Invalid refresh token"));
    }

    private CachedRefreshToken getRefereshTokenFromToken(String token) {
        String cacheTokenKey = buildCacheKey(token);
        CachedRefreshToken cached = cacheService.getValue(cacheTokenKey, CachedRefreshToken.class);
        if (cached != null) {
            return cached;
        }

        CachedRefreshToken refereshToken = refereshTokenRepository.findByRefreshToken(token)
                .map(found -> new CachedRefreshToken(found.getId(), found.getUser().getId(), found.getExpiryDate()))
                .orElse(null);
        if (refereshToken != null) {
            cacheService.save(cacheTokenKey, refereshToken, expireTime);
        }
        return refereshToken;
    }

    // Not "refreshToken-", the prefix used while entries held the whole user: those
    // entries must not be read back.
    private String buildCacheKey(String token) {
        return "refresh-token:" + token;
    }
}
