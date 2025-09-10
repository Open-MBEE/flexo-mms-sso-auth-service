package org.openmbee.flexo.mms.sso.service;

import org.openmbee.flexo.mms.sso.entity.ApiKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class UserService {

    private final ApiKeyService apiKeyService;

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
}
