package com.maruf.oauth.controller;

import com.maruf.oauth.dto.AuthStatusResponse;
import com.maruf.oauth.dto.UserResponse;
import com.maruf.oauth.util.OAuth2AttributeExtractor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Slf4j
public class AuthController {

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
}