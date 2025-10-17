package com.maruf.oauth.service;

import com.maruf.oauth.entity.InvalidatedToken;
import com.maruf.oauth.entity.RefreshToken;
import com.maruf.oauth.repository.InvalidatedTokenRepository;
import com.maruf.oauth.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Instant;

@Service
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenStore {

    private final RefreshTokenRepository refreshTokenRepository;
    private final InvalidatedTokenRepository invalidatedTokenRepository;

    public void storeRefreshToken(String token, String username, Instant expiresAt) {
        RefreshToken refreshToken = RefreshToken.builder()
                .token(token)
                .username(username)
                .expiresAt(expiresAt)
                .createdAt(Instant.now())
                .lastUsed(Instant.now())
                .build();
        
        refreshTokenRepository.save(refreshToken);
        log.debug("Stored refresh token for user: {}", username);
    }

    public String getUsernameFromRefreshToken(String token) {
        return refreshTokenRepository.findByToken(token)
                .map(refreshToken -> {
                    // Update last used timestamp
                    refreshToken.setLastUsed(Instant.now());
                    refreshTokenRepository.save(refreshToken);
                    return refreshToken.getUsername();
                })
                .orElse(null);
    }

    public void invalidateRefreshToken(String token) {
        refreshTokenRepository.deleteByToken(token);
        log.debug("Refresh token invalidated");
    }

    public void invalidateAccessToken(String token, String username, Instant expiresAt) {
        InvalidatedToken invalidatedToken = InvalidatedToken.builder()
                .token(token)
                .username(username)
                .expiresAt(expiresAt)
                .invalidatedAt(Instant.now())
                .reason("logout")
                .build();
        
        invalidatedTokenRepository.save(invalidatedToken);
        log.debug("Access token invalidated");
    }

    public boolean isAccessTokenInvalidated(String token) {
        return invalidatedTokenRepository.existsByToken(token);
    }
}