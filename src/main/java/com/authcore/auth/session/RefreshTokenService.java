package com.authcore.auth.session;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;

import com.authcore.auth.common.AuthConfigProperties;
import com.authcore.auth.common.CacheService;
import com.authcore.auth.common.DeadlockRetry;
import com.authcore.auth.token.InvalidTokenException;
import com.authcore.auth.token.TokenExpireException;
import com.authcore.auth.user.User;
import com.authcore.auth.user.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {
    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final CacheService<String, CachedRefreshToken> cacheService;
    private final AuthConfigProperties authConfigProperties;

    public RefreshToken createRefreshToken(User user) {
        return DeadlockRetry.run(() -> tryToCreateRefreshToken(user));
    }

    private RefreshToken tryToCreateRefreshToken(User user) {
        RefreshToken refreshToken = refreshTokenRepository.findByUser(user).orElse(null);
        if (refreshToken != null && refreshToken.getExpiryDate().isAfter(Instant.now())) {
            return refreshToken;
        }

        if (refreshToken != null) {
            refreshTokenRepository.deleteAllByIdInBatch(List.of(refreshToken.getId()));
        }

        refreshToken = RefreshToken.builder().refreshToken(UUID.randomUUID().toString())
                .expiryDate(Instant.now().plusMillis(expireTime())).user(user).build();
        try {
            return refreshTokenRepository.save(refreshToken);
        } catch (DataIntegrityViolationException e) {
            // Another login of this user created the token at the same moment: share it.
            return refreshTokenRepository.findByUser(user).orElseThrow(() -> e);
        }
    }

    public void deleteRefreshToken(User user) {
        refreshTokenRepository.findByUser(user)
                .ifPresent(token -> refreshTokenRepository.deleteAllByIdInBatch(List.of(token.getId())));
    }

    /** Returns the user this refresh token belongs to. */
    public User verifyRefreshToken(String token) {
        // Never echo the token: error responses and logs must not contain it (H2).
        CachedRefreshToken refreshToken = getRefreshTokenFromToken(token);
        if (refreshToken == null) {
            throw new InvalidTokenException("Invalid refresh token");
        }
        if (refreshToken.expiryDate().isBefore(Instant.now())) {
            refreshTokenRepository.deleteAllByIdInBatch(List.of(refreshToken.tokenId()));
            throw new TokenExpireException("Refresh token has expired");
        }
        // Always from the database: a cached token can outlive its user's account.
        return userRepository.findById(refreshToken.userId())
                .orElseThrow(() -> new InvalidTokenException("Invalid refresh token"));
    }

    private CachedRefreshToken getRefreshTokenFromToken(String token) {
        String cacheTokenKey = buildCacheKey(token);
        CachedRefreshToken cached = cacheService.getValue(cacheTokenKey, CachedRefreshToken.class);
        if (cached != null) {
            return cached;
        }

        CachedRefreshToken refreshToken = refreshTokenRepository.findByRefreshToken(token)
                .map(found -> new CachedRefreshToken(found.getId(), found.getUser().getId(), found.getExpiryDate()))
                .orElse(null);
        if (refreshToken != null) {
            cacheService.save(cacheTokenKey, refreshToken, expireTime());
        }
        return refreshToken;
    }

    private long expireTime() {
        return authConfigProperties.getToken().getRefreshExpiration();
    }

    // Not "refreshToken-", the prefix used while entries held the whole user: those
    // entries must not be read back.
    private String buildCacheKey(String token) {
        return "refresh-token:" + token;
    }
}
