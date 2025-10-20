package com.maruf.oauth.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Writes a JSON body when logout completes to support SPA clients.
 * Keeps a lightweight {@link ObjectMapper} instance for serialising success payloads.
 *
 * @author Maruf Bepary
 */
@Component
@Slf4j
public class JsonLogoutSuccessHandler implements LogoutSuccessHandler {

    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Outputs a simple JSON confirmation when a logout request is processed.
     * Logs the username for traceability while tolerating anonymous contexts.
     *
     * @param request        servlet request triggering the logout
     * @param response       servlet response used to send the JSON payload
     * @param authentication current authentication context, may be {@code null} after logout
     * @author Maruf Bepary
     */
    @Override
    public void onLogoutSuccess(HttpServletRequest request,
                                HttpServletResponse response,
                                Authentication authentication) throws IOException, ServletException {
        
        String username = authentication != null ? authentication.getName() : "unknown";
        log.info("User '{}' logged out successfully", username);

        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        Map<String, Object> data = new HashMap<>();
        data.put("success", true);
        data.put("message", "Logout successful");

        response.getWriter().write(objectMapper.writeValueAsString(data));
    }
}