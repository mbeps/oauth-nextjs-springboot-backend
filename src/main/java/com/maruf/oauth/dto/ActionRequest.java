package com.maruf.oauth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ActionRequest {
    @NotBlank(message = "Action cannot be blank")
    @Size(max = 50, message = "Action must be less than 50 characters")
    private String action;
}