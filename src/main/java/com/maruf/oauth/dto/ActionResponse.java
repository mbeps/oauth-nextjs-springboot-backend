package com.maruf.oauth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ActionResponse {
    private String message;
    private String user;
    private String action;
    private String result;
    private Long timestamp;
}