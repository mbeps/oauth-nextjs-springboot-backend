package com.maruf.oauth.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@Slf4j
@CrossOrigin(origins = "http://localhost:3000", allowCredentials = "true")
public class AuthController {

    @GetMapping("/api/auth/status")
    public ResponseEntity<Map<String, Object>> getAuthStatus(@AuthenticationPrincipal OAuth2User principal) {
        Map<String, Object> response = new HashMap<>();
        
        if (principal != null) {
            response.put("authenticated", true);
            response.put("user", Map.of(
                "id", principal.getAttribute("id"),
                "login", principal.getAttribute("login"),
                "name", principal.getAttribute("name"),
                "avatar_url", principal.getAttribute("avatar_url")
            ));
            log.info("Auth status checked for user: {}", (Object) principal.getAttribute("login"));
        } else {
            response.put("authenticated", false);
            log.info("Auth status checked - user not authenticated");
        }
        
        return ResponseEntity.ok(response);
    }
}