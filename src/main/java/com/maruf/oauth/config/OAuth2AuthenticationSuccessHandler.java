package com.maruf.oauth.config;

import com.maruf.oauth.service.JwtService;
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

@Component
@RequiredArgsConstructor
@Slf4j
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtService jwtService;

    @Value("${frontend.url:http://localhost:3000}")
    private String frontendUrl;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, 
                                       HttpServletResponse response,
                                       Authentication authentication) throws IOException {
        
        OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();
        String username = oauth2User.getAttribute("login");
        
        // Generate JWT token
        String token = jwtService.generateToken(oauth2User);
        
        // Set JWT as httpOnly cookie
        Cookie jwtCookie = new Cookie("jwt", token);
        jwtCookie.setHttpOnly(true);
        jwtCookie.setSecure(false); // Set to true in production with HTTPS
        jwtCookie.setPath("/");
        jwtCookie.setMaxAge(24 * 60 * 60); // 24 hours
        response.addCookie(jwtCookie);
        
        log.info("JWT token generated and set in cookie for user: {}", username);
        
        // Redirect to frontend dashboard
        getRedirectStrategy().sendRedirect(request, response, frontendUrl + "/dashboard");
    }
}