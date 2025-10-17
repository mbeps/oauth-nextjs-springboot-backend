package com.maruf.oauth.config;

import com.maruf.oauth.service.JwtService;
import com.maruf.oauth.service.RefreshTokenStore;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;

@Component
@RequiredArgsConstructor
@Slf4j
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtService jwtService;
    private final RefreshTokenStore refreshTokenStore;
    private final CookieSecurityProperties cookieSecurityProperties;

    @Value("${frontend.url:http://localhost:3000}")
    private String frontendUrl;

    @Value("${jwt.access-token-expiration:900000}") // 15 minutes
    private Long accessTokenExpiration;

    @Value("${jwt.refresh-token-expiration:604800000}") // 7 days
    private Long refreshTokenExpiration;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, 
                                       HttpServletResponse response,
                                       Authentication authentication) throws IOException {
        
        OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();
        String username = oauth2User.getAttribute("login");
        
        // Generate access token (short-lived)
        String accessToken = jwtService.generateAccessToken(oauth2User);
        
        // Generate refresh token (long-lived)
        String refreshToken = jwtService.generateRefreshToken(username);
        
        // Store refresh token
        Instant refreshExpiresAt = Instant.now().plusMillis(refreshTokenExpiration);
        refreshTokenStore.storeRefreshToken(refreshToken, username, refreshExpiresAt);
        
        // Set access token as httpOnly cookie
        Cookie accessCookie = createSecureCookie("jwt", accessToken, 
                (int) (accessTokenExpiration / 1000));
        response.addCookie(accessCookie);
        
        // Set refresh token as httpOnly cookie
        Cookie refreshCookie = createSecureCookie("refresh_token", refreshToken, 
                (int) (refreshTokenExpiration / 1000));
        response.addCookie(refreshCookie);
        
        log.info("Access and refresh tokens generated for user: {}", username);
        
        // Redirect to frontend dashboard
        getRedirectStrategy().sendRedirect(request, response, frontendUrl + "/dashboard");
    }

    private Cookie createSecureCookie(String name, String value, int maxAge) {
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(true);
        cookie.setSecure(cookieSecurityProperties.isSecure());
        cookie.setPath("/");
        cookie.setMaxAge(maxAge);
        // Note: SameSite attribute requires Servlet 6.0+ or manual header manipulation
        return cookie;
    }
}