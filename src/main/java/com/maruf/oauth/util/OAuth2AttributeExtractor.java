package com.maruf.oauth.util;

import org.springframework.security.oauth2.core.user.OAuth2User;

/**
 * Provides helpers for reading OAuth2 attributes with predictable types.
 * Normalises common GitHub claim shapes so controllers stay concise.
 *
 * @author Maruf Bepary
 */
public class OAuth2AttributeExtractor {

    /**
     * Returns an attribute as an {@link Integer} when available.
     * Handles OAuth providers that emit numeric identifiers as Integer, Long, or other {@link Number} types.
     *
     * @param principal     authenticated OAuth2 user supplying attribute data
     * @param attributeName attribute key expected from the provider
     * @author Maruf Bepary
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
     * Returns an attribute as a {@link String} while tolerating nulls.
     * Uses {@link Object#toString()} to mirror Spring Security's default conversion rules.
     *
     * @param principal     authenticated OAuth2 user supplying attribute data
     * @param attributeName attribute key expected from the provider
     * @author Maruf Bepary
     */
    public static String getStringAttribute(OAuth2User principal, String attributeName) {
        Object attribute = principal.getAttribute(attributeName);
        return attribute != null ? attribute.toString() : null;
    }
}