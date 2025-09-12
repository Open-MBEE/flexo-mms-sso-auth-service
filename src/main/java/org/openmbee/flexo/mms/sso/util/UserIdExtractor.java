package org.openmbee.flexo.mms.sso.util;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

/**
 * Utility class to consistently extract userId from various authentication types.
 * This ensures that the same userId is used throughout the application.
 */
@Component
public class UserIdExtractor {

    @Value("${flexo.sso-auth-service.sso_user_id_field:null}")
    private String ssoUserIdField;
    
    @Value("${flexo.sso-auth-service.jwt_user_id_field:sub}")
    private String jwtUserIdField;
    
    /**
     * Extract userId from an Authentication object
     * 
     * @param authentication The authentication object
     * @return The extracted userId
     */
    public String extractUserId(Authentication authentication) {
        if (authentication == null) {
            return "anonymous";
        }
        
        if (authentication.getPrincipal() instanceof OidcUser) {
            return extractUserIdFromOidcUser((OidcUser) authentication.getPrincipal());
        } else if (authentication.getPrincipal() instanceof String) {
            return (String) authentication.getPrincipal();
        }
        
        return authentication.getName();
    }
    
    /**
     * Extract userId from an OidcUser object
     * 
     * @param oidcUser The OidcUser object
     * @return The extracted userId
     */
    public String extractUserIdFromOidcUser(OidcUser oidcUser) {
        if (oidcUser == null) {
            return "anonymous";
        }
        
        // First try the configured claim field
        if (ssoUserIdField != null && !ssoUserIdField.equals("null")) {
            Object userIdObj = oidcUser.getClaims().get(ssoUserIdField);
            if (userIdObj != null) {
                return userIdObj.toString();
            }
        }
        
        // Fallback to standard subject claim
        return oidcUser.getSubject();
    }
    
    /**
     * Extract userId from a Jwt token
     * 
     * @param jwt The Jwt token
     * @return The extracted userId
     */
    public String extractUserIdFromJwt(Jwt jwt) {
        if (jwt == null) {
            return "anonymous";
        }
        
        // Try to extract from configured field
        if (jwtUserIdField != null && !jwtUserIdField.equals("null") && jwt.hasClaim(jwtUserIdField)) {
            return jwt.getClaimAsString(jwtUserIdField);
        }
        
        // Fallbacks in priority order
        if (jwt.hasClaim("sub")) {
            return jwt.getSubject();
        } else if (jwt.hasClaim("email")) {
            return jwt.getClaimAsString("email");
        } else if (jwt.hasClaim("preferred_username")) {
            return jwt.getClaimAsString("preferred_username");
        }
        
        return "unknown";
    }
}