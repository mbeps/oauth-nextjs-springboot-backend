package com.maruf.oauth.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "cookie")
@Data
public class CookieSecurityProperties {
    
    private boolean secure = false;
    private String sameSite = "Lax";
}