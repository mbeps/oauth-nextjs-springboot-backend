package com.maruf.oauth.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory storage for refresh tokens.
 * Note: Tokens will be lost on server restart. For production, use Redis or a database.
 */
@Service
@Slf4j
public class RefreshTokenStore {

    private final Map<String, TokenData> refreshTokens = new ConcurrentHashMap<>();
    private final Map<String, String> invalidatedAccessTokens = new ConcurrentHashMap<>();

    public void storeRefreshToken(String token, String username, Instant expiresAt) {
        refreshTokens.put(token, new TokenData(username, expiresAt));
        log.debug("Stored refresh token for user: {}", username);
    }

    public String getUsernameFromRefreshToken(String token) {
        TokenData data = refreshTokens.get(token);
        if (data == null) {
            return null;
        }
        
        // Check if expired
        if (data.expiresAt.isBefore(Instant.now())) {
            refreshTokens.remove(token);
            log.debug("Refresh token expired and removed");
            return null;
        }
        
        return data.username;
    }

    public void invalidateRefreshToken(String token) {
        refreshTokens.remove(token);
        log.debug("Refresh token invalidated");
    }

    public void invalidateAccessToken(String token) {
        // Store invalidated access tokens until they expire naturally
        invalidatedAccessTokens.put(token, Instant.now().toString());
        log.debug("Access token invalidated");
    }

    public boolean isAccessTokenInvalidated(String token) {
        return invalidatedAccessTokens.containsKey(token);
    }

    public void cleanupExpiredTokens() {
        Instant now = Instant.now();
        refreshTokens.entrySet().removeIf(entry -> entry.getValue().expiresAt.isBefore(now));
        log.debug("Cleaned up expired tokens");
    }

    private record TokenData(String username, Instant expiresAt) {}
}