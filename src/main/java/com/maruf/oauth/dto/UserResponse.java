package com.maruf.oauth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserResponse {
    private Integer id;  // Changed from Long to Integer (GitHub returns Integer)
    private String login;
    private String name;
    private String email;
    private String avatarUrl;
}