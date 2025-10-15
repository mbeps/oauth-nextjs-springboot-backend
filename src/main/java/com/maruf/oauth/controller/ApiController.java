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
public class ApiController {

    @GetMapping("/api/public/health")
    public ResponseEntity<Map<String, Object>> publicHealth() {
        Map<String, Object> response = new HashMap<>();
        response.put("status", "OK");
        response.put("message", "Public endpoint is working");
        response.put("timestamp", System.currentTimeMillis());
        
        log.info("Public health endpoint accessed");
        return ResponseEntity.ok(response);
    }

    @GetMapping("/api/user")
    public ResponseEntity<Map<String, Object>> getUser(@AuthenticationPrincipal OAuth2User principal) {
        if (principal == null) {
            return ResponseEntity.status(401).build();
        }

        Map<String, Object> response = new HashMap<>();
        response.put("id", principal.getAttribute("id"));
        response.put("login", principal.getAttribute("login"));
        response.put("name", principal.getAttribute("name"));
        response.put("email", principal.getAttribute("email"));
        response.put("avatar_url", principal.getAttribute("avatar_url"));
        
        log.info("User info requested for: {}", (Object) principal.getAttribute("login"));
        return ResponseEntity.ok(response);
    }

    @GetMapping("/api/protected/data")
    public ResponseEntity<Map<String, Object>> getProtectedData(@AuthenticationPrincipal OAuth2User principal) {
        if (principal == null) {
            return ResponseEntity.status(401).build();
        }

        Map<String, Object> response = new HashMap<>();
        response.put("message", "This is protected data");
        response.put("user", principal.getAttribute("login"));
        response.put("data", Map.of(
            "items", new String[]{"Item 1", "Item 2", "Item 3"},
            "count", 3,
            "lastUpdated", System.currentTimeMillis()
        ));
        
        log.info("Protected data accessed by: {}", (Object) principal.getAttribute("login"));
        return ResponseEntity.ok(response);
    }

    @PostMapping("/api/protected/action")
    public ResponseEntity<Map<String, Object>> performAction(
            @AuthenticationPrincipal OAuth2User principal,
            @RequestBody Map<String, Object> requestData) {
        
        if (principal == null) {
            return ResponseEntity.status(401).build();
        }

        Map<String, Object> response = new HashMap<>();
        response.put("message", "Action performed successfully");
        response.put("user", principal.getAttribute("login"));
        response.put("action", requestData.get("action"));
        response.put("result", "Success");
        response.put("timestamp", System.currentTimeMillis());
        
        log.info("Action '{}' performed by: {}", requestData.get("action"), (Object) principal.getAttribute("login"));
        return ResponseEntity.ok(response);
    }
}