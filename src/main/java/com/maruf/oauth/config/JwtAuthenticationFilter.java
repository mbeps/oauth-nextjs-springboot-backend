package com.maruf.oauth.config;

import com.maruf.oauth.service.JwtService;
import com.maruf.oauth.service.RefreshTokenStore;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final RefreshTokenStore refreshTokenStore;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                   @NonNull HttpServletResponse response,
                                   @NonNull FilterChain filterChain) throws ServletException, IOException {
        
        String jwt = extractJwtFromCookie(request);
        
        if (jwt != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            try {
                // Check if token is invalidated
                if (refreshTokenStore.isAccessTokenInvalidated(jwt)) {
                    log.debug("JWT is invalidated");
                    filterChain.doFilter(request, response);
                    return;
                }
                
                if (jwtService.isTokenValid(jwt) && !jwtService.isTokenExpired(jwt)) {
                    // Verify it's an access token
                    String tokenType = jwtService.extractTokenType(jwt);
                    if (!"access".equals(tokenType)) {
                        log.debug("Token is not an access token");
                        filterChain.doFilter(request, response);
                        return;
                    }
                    
                    Claims claims = jwtService.extractAllClaims(jwt);
                    
                    // Reconstruct OAuth2User from JWT claims
                    // Handle Integer type properly (GitHub returns Integer for id)
                    Map<String, Object> attributes = new HashMap<>();
                    Object idClaim = claims.get("id");
                    if (idClaim instanceof Integer) {
                        attributes.put("id", idClaim);
                    } else if (idClaim instanceof Long) {
                        attributes.put("id", ((Long) idClaim).intValue());
                    } else if (idClaim instanceof Number) {
                        attributes.put("id", ((Number) idClaim).intValue());
                    }
                    
                    attributes.put("login", claims.get("login"));
                    attributes.put("name", claims.get("name"));
                    attributes.put("email", claims.get("email"));
                    attributes.put("avatar_url", claims.get("avatar_url"));
                    
                    OAuth2User oauth2User = new DefaultOAuth2User(
                            Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")),
                            attributes,
                            "login"
                    );
                    
                    UsernamePasswordAuthenticationToken authentication = 
                        new UsernamePasswordAuthenticationToken(
                            oauth2User,
                            null,
                            oauth2User.getAuthorities()
                        );
                    
                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                    
                    log.debug("JWT validated for user: {}", claims.get("login"));
                }
            } catch (Exception e) {
                log.error("JWT validation failed: {}", e.getMessage());
            }
        }
        
        filterChain.doFilter(request, response);
    }

    private String extractJwtFromCookie(HttpServletRequest request) {
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if ("jwt".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }
}