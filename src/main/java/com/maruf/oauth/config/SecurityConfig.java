package com.maruf.oauth.config;

import com.maruf.oauth.service.JwtService;
import com.maruf.oauth.service.RefreshTokenStore;
import jakarta.servlet.http.Cookie;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final OAuth2AuthenticationSuccessHandler oauth2SuccessHandler;
    private final RefreshTokenStore refreshTokenStore;
    private final JwtService jwtService;
    private final CookieSecurityProperties cookieSecurityProperties;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .csrf(csrf -> csrf.disable())
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            .authorizeHttpRequests(authz -> authz
                .requestMatchers("/", "/login", "/error", "/webjars/**").permitAll()
                .requestMatchers("/api/public/**").permitAll()
                .requestMatchers("/api/auth/status").permitAll()
                .requestMatchers("/api/auth/refresh").permitAll()
                .requestMatchers("/logout").permitAll()
                .anyRequest().authenticated()
            )
            .oauth2Login(oauth2 -> oauth2
                .successHandler(oauth2SuccessHandler)
                .failureUrl("http://localhost:3000/?error=auth_failed")
            )
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessHandler((request, response, authentication) -> {
                    // Invalidate tokens
                    if (request.getCookies() != null) {
                        for (Cookie cookie : request.getCookies()) {
                            if ("jwt".equals(cookie.getName())) {
                                // Get token expiry date for storage
                                java.time.Instant expiresAt = jwtService.getExpirationDate(cookie.getValue()).toInstant();
                                String username = jwtService.extractUsername(cookie.getValue());
                                refreshTokenStore.invalidateAccessToken(cookie.getValue(), username, expiresAt);
                            } else if ("refresh_token".equals(cookie.getName())) {
                                refreshTokenStore.invalidateRefreshToken(cookie.getValue());
                            }
                        }
                    }
                    
                    // Delete JWT cookie
                    Cookie jwtCookie = createSecureCookie("jwt", null);
                    response.addCookie(jwtCookie);
                    
                    // Delete refresh token cookie
                    Cookie refreshCookie = createSecureCookie("refresh_token", null);
                    response.addCookie(refreshCookie);
                    
                    // Return JSON response
                    response.setStatus(200);
                    response.setContentType("application/json");
                    response.getWriter().write("{\"success\":true,\"message\":\"Logout successful\"}");
                })
                .deleteCookies("jwt", "refresh_token")
            )
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("http://localhost:3000"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("Content-Type", "Authorization"));
        configuration.setAllowCredentials(true);
        
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    private Cookie createSecureCookie(String name, String value) {
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(true);
        cookie.setSecure(cookieSecurityProperties.isSecure());
        cookie.setPath("/");
        cookie.setMaxAge(0);
        return cookie;
    }
}