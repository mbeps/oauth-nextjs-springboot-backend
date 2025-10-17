package com.maruf.oauth.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Instant;

@Document(collection = "invalidated_access_tokens")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class InvalidatedToken {
    
    @Id
    private String id;
    
    @Indexed(unique = true)
    private String token;
    
    private String username;
    
    @Indexed(expireAfterSeconds = 0)
    private Instant expiresAt;
    
    private Instant invalidatedAt;
    
    private String reason;
}