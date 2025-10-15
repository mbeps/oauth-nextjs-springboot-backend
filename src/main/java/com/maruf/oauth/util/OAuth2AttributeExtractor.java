package com.maruf.oauth.util;

import org.springframework.security.oauth2.core.user.OAuth2User;

/**
 * Utility class for safely extracting attributes from OAuth2User.
 * Handles type conversions to prevent ClassCastException.
 */
public class OAuth2AttributeExtractor {

    /**
     * Safely extracts Integer attribute from OAuth2User.
     * Handles both Integer and Long types from different sources (OAuth, JWT).
     */
    public static Integer getIntegerAttribute(OAuth2User principal, String attributeName) {
        Object attribute = principal.getAttribute(attributeName);
        if (attribute == null) {
            return null;
        }
        if (attribute instanceof Integer) {
            return (Integer) attribute;
        }
        if (attribute instanceof Long) {
            return ((Long) attribute).intValue();
        }
        if (attribute instanceof Number) {
            return ((Number) attribute).intValue();
        }
        return null;
    }

    /**
     * Safely extracts String attribute from OAuth2User.
     */
    public static String getStringAttribute(OAuth2User principal, String attributeName) {
        Object attribute = principal.getAttribute(attributeName);
        return attribute != null ? attribute.toString() : null;
    }
}