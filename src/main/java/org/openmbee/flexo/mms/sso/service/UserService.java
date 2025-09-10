package org.openmbee.flexo.mms.sso.service;

import org.openmbee.flexo.mms.sso.entity.ApiKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class UserService {

    private final ApiKeyService apiKeyService;
    
    @Value("${flexo.sso-auth-service.group_claims_field:groups}")
    private String groupClaimsField;

    @Autowired
    public UserService(ApiKeyService apiKeyService) {
        this.apiKeyService = apiKeyService;
    }

    public Map<String, Object> getUserDetails(Authentication authentication) {
        Map<String, Object> userDetails = new HashMap<>();

        String userId = null;

        if (authentication.getPrincipal() instanceof OidcUser) {
            OidcUser oidcUser = (OidcUser) authentication.getPrincipal();
            userId = oidcUser.getSubject();
            userDetails.put("name", oidcUser.getFullName());
            userDetails.put("email", oidcUser.getEmail());
            userDetails.put("claims", oidcUser.getClaims());
        } else {
            userId = authentication.getName();
            userDetails.put("name", userId);
        }

        // Get API keys for user
        List<ApiKey> apiKeys = apiKeyService.getApiKeysForUser(userId);
        userDetails.put("apiKeys", apiKeys);
        userDetails.put("userId", userId);

        return userDetails;
    }
    
    /**
     * Get user groups from SSO claims or fall back to SPARQL
     * 
     * @param username The username of the user
     * @return A list of group identifiers
     */
    public List<String> getUserGroups(String username) {
        // First, check for a current SSO session with claims containing groups
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        
        if (authentication != null && authentication.getPrincipal() instanceof OidcUser) {
            OidcUser oidcUser = (OidcUser) authentication.getPrincipal();
            Map<String, Object> claims = oidcUser.getClaims();
            
            // Check if groups are provided in claims using configured field name
            if (claims.containsKey(groupClaimsField)) {
                Object groupsObj = claims.get(groupClaimsField);
                if (groupsObj instanceof List) {
                    @SuppressWarnings("unchecked")
                    List<String> groups = (List<String>) groupsObj;
                    return groups;
                }
            }
        }
        
        // If no groups found in SSO claims, return null
        return null;
    }
}
