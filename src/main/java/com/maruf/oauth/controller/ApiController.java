package com.maruf.oauth.controller;

import com.maruf.oauth.dto.*;
import com.maruf.oauth.util.OAuth2AttributeExtractor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.*;

@RestController
@Slf4j
public class ApiController {

    @GetMapping("/api/public/health")
    public ResponseEntity<PublicHealthResponse> publicHealth() {
        PublicHealthResponse response = PublicHealthResponse.builder()
                .status("OK")
                .message("Public endpoint is working")
                .timestamp(System.currentTimeMillis())
                .build();
        
        log.info("Public health endpoint accessed");
        return ResponseEntity.ok(response);
    }

    @GetMapping("/api/user")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<UserResponse> getUser(@AuthenticationPrincipal OAuth2User principal) {
        UserResponse response = UserResponse.builder()
                .id(OAuth2AttributeExtractor.getIntegerAttribute(principal, "id"))
                .login(OAuth2AttributeExtractor.getStringAttribute(principal, "login"))
                .name(OAuth2AttributeExtractor.getStringAttribute(principal, "name"))
                .email(OAuth2AttributeExtractor.getStringAttribute(principal, "email"))
                .avatarUrl(OAuth2AttributeExtractor.getStringAttribute(principal, "avatar_url"))
                .build();
        
        log.info("User info requested for: {}", response.getLogin());
        return ResponseEntity.ok(response);
    }

    @GetMapping("/api/protected/data")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<ProtectedDataResponse> getProtectedData(@AuthenticationPrincipal OAuth2User principal) {
        String username = OAuth2AttributeExtractor.getStringAttribute(principal, "login");
        
        ProtectedDataResponse.DataContent dataContent = ProtectedDataResponse.DataContent.builder()
                .items(new String[]{"Item 1", "Item 2", "Item 3"})
                .count(3)
                .lastUpdated(System.currentTimeMillis())
                .build();
        
        ProtectedDataResponse response = ProtectedDataResponse.builder()
                .message("This is protected data")
                .user(username)
                .data(dataContent)
                .build();
        
        log.info("Protected data accessed by: {}", username);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/api/protected/action")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<ActionResponse> performAction(
            @AuthenticationPrincipal OAuth2User principal,
            @RequestBody ActionRequest request) {
        
        String username = OAuth2AttributeExtractor.getStringAttribute(principal, "login");
        
        ActionResponse response = ActionResponse.builder()
                .message("Action performed successfully")
                .user(username)
                .action(request.getAction())
                .result("Success")
                .timestamp(System.currentTimeMillis())
                .build();
        
        log.info("Action '{}' performed by: {}", request.getAction(), username);
        return ResponseEntity.ok(response);
    }
}