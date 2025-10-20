package com.maruf.oauth.controller;

import com.maruf.oauth.config.CookieSecurityProperties;
import com.maruf.oauth.dto.AuthStatusResponse;
import com.maruf.oauth.dto.UserResponse;
import com.maruf.oauth.service.JwtService;
import com.maruf.oauth.service.RefreshTokenStore;
import com.maruf.oauth.util.OAuth2AttributeExtractor;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Manages authentication lifecycle endpoints such as status checks and token refresh.
 * Coordinates JWT generation with cookie settings to match the Next.js client flow.
 *
 * @author Maruf Bepary
 */
@RestController
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final JwtService jwtService;
    private final RefreshTokenStore refreshTokenStore;
    private final CookieSecurityProperties cookieSecurityProperties;

    @Value("${jwt.access-token-expiration:900000}") // 15 minutes
    private Long accessTokenExpiration;

    /**
     * Returns whether the current request is authenticated and, if so, the associated profile.
     * Builds the DTO manually to keep tight control over which OAuth fields leave the server.
     *
     * @param principal the authenticated principal resolved by Spring Security, may be {@code null}
     * @author Maruf Bepary
     */
    @GetMapping("/api/auth/status")
    public ResponseEntity<AuthStatusResponse> getAuthStatus(@AuthenticationPrincipal OAuth2User principal) {
        
        if (principal != null) {
            UserResponse user = UserResponse.builder()
                    .id(OAuth2AttributeExtractor.getIntegerAttribute(principal, "id"))
                    .login(OAuth2AttributeExtractor.getStringAttribute(principal, "login"))
                    .name(OAuth2AttributeExtractor.getStringAttribute(principal, "name"))
                    .email(OAuth2AttributeExtractor.getStringAttribute(principal, "email"))
                    .avatarUrl(OAuth2AttributeExtractor.getStringAttribute(principal, "avatar_url"))
                    .build();

            log.info("Auth status checked for user: {}", user.getLogin());
            
            return ResponseEntity.ok(
                AuthStatusResponse.builder()
                    .authenticated(true)
                    .user(user)
                    .build()
            );
        } else {
            log.info("Auth status checked - user not authenticated");
            return ResponseEntity.ok(
                AuthStatusResponse.builder()
                    .authenticated(false)
                    .build()
            );
        }
    }

    /**
     * Issues a new access token when a valid refresh token cookie is presented.
     * Reuses a minimal {@link OAuth2User} instance so downstream JWT code remains shared with login.
     *
     * @param request  HTTP servlet request containing authentication cookies
     * @param response HTTP servlet response used to publish a renewed access token cookie
     * @author Maruf Bepary
     */
    @PostMapping("/api/auth/refresh")
    public ResponseEntity<Map<String, Object>> refreshToken(HttpServletRequest request, HttpServletResponse response) {
        // Extract refresh token from cookie
        String refreshToken = null;
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if ("refresh_token".equals(cookie.getName())) {
                    refreshToken = cookie.getValue();
                    break;
                }
            }
        }

        if (refreshToken == null) {
            log.warn("Refresh token not found in cookies");
            return ResponseEntity.status(401).body(Map.of("error", "Refresh token not found"));
        }

        // Validate refresh token and get username
        String username = refreshTokenStore.getUsernameFromRefreshToken(refreshToken);
        if (username == null) {
            log.warn("Invalid or expired refresh token");
            return ResponseEntity.status(401).body(Map.of("error", "Invalid refresh token"));
        }

        try {
            // Validate the refresh token itself with JWT
            if (!jwtService.isTokenValid(refreshToken) || jwtService.isTokenExpired(refreshToken)) {
                log.warn("Refresh token is invalid or expired");
                refreshTokenStore.invalidateRefreshToken(refreshToken);
                return ResponseEntity.status(401).body(Map.of("error", "Refresh token expired"));
            }

            // Create a minimal OAuth2User for token generation
            Map<String, Object> attributes = new HashMap<>();
            attributes.put("login", username);
            
            OAuth2User oauth2User = new DefaultOAuth2User(
                    Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")),
                    attributes,
                    "login"
            );

            // Generate new access token
            String newAccessToken = jwtService.generateAccessToken(oauth2User);

            // Set new access token as cookie
            Cookie accessCookie = createSecureCookie("jwt", newAccessToken, 
                    (int) (accessTokenExpiration / 1000));
            response.addCookie(accessCookie);

            log.info("Access token refreshed for user: {}", username);

            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "message", "Token refreshed successfully"
            ));
        } catch (Exception e) {
            log.error("Error refreshing token: {}", e.getMessage());
            return ResponseEntity.status(500).body(Map.of("error", "Token refresh failed"));
        }
    }

    /**
     * Creates an HTTP only cookie aligned with the configured security rules.
     * Centralises cookie flags to avoid divergent settings across authentication responses.
     *
     * @param name   cookie name, typically identifying the token type
     * @param value  token value persisted inside the cookie
     * @param maxAge lifetime in seconds before the cookie expires on the client
     * @author Maruf Bepary
     */
    private Cookie createSecureCookie(String name, String value, int maxAge) {
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(true);
        cookie.setSecure(cookieSecurityProperties.isSecure());
        cookie.setPath("/");
        cookie.setMaxAge(maxAge);
        return cookie;
    }
}