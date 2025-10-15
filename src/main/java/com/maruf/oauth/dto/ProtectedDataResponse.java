package com.maruf.oauth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ProtectedDataResponse {
    private String message;
    private String user;
    private DataContent data;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class DataContent {
        private String[] items;
        private Integer count;
        private Long lastUpdated;
    }
}