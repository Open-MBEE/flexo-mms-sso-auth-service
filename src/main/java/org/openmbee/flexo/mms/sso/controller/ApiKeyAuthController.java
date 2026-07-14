package org.openmbee.flexo.mms.sso.controller;

import org.openmbee.flexo.mms.sso.entity.ApiKey;
import org.openmbee.flexo.mms.sso.exception.UnauthorizedException;
import org.openmbee.flexo.mms.sso.service.ApiKeyService;
import org.openmbee.flexo.mms.sso.service.ProvisioningService;
import org.openmbee.flexo.mms.sso.service.TokenSigner;
import org.openmbee.flexo.mms.sso.service.UserService;
import org.openmbee.flexo.mms.sso.util.UserIdExtractor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@RestController
public class ApiKeyAuthController {

    private final ApiKeyService apiKeyService;
    private final UserService userService;
    private final UserIdExtractor userIdExtractor;
    private final TokenSigner tokenSigner;
    private final ProvisioningService provisioningService;

    @Value("${jwt.duration:86400000}")
    private int jwtDurationMilliseconds;

    @Autowired
    public ApiKeyAuthController(ApiKeyService apiKeyService, UserService userService,
                                UserIdExtractor userIdExtractor, TokenSigner tokenSigner,
                                ProvisioningService provisioningService) {
        this.apiKeyService = apiKeyService;
        this.userService = userService;
        this.userIdExtractor = userIdExtractor;
        this.tokenSigner = tokenSigner;
        this.provisioningService = provisioningService;
    }

    @GetMapping("/login")
    public Map<String, String> login(@RequestHeader(value="Authorization", required=false) String authHeader,
                                   @RequestHeader(value="X-API-KEY", required=false) String xApiKey) {
        // Extract API key from Authorization header if present
        String apiKey = null;
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            apiKey = authHeader.substring(7);
        } else if (xApiKey != null) { // For backward compatibility
            apiKey = xApiKey;
        }

        // Validate API key
        if (apiKey != null && !apiKey.isEmpty()) {
            Optional<ApiKey> validatedKey = apiKeyService.validateApiKey(apiKey);

            if (validatedKey.isPresent()) {
                ApiKey key = validatedKey.get();
                String username = key.getUserId(); // Using userId as username consistently

                // Get user groups from SSO claims
                List<String> availableGroups = userService.getUserGroups(username);

                // Ensure layer1 orgs/groups/policies exist for org-encoding groups (no-op if disabled)
                provisioningService.provisionForGroups(availableGroups);

                // Generate JWT token with username
                String token = tokenSigner.sign(username, availableGroups, jwtDurationMilliseconds);

                // Return in same format as flexo-mms-auth-service
                return Collections.singletonMap("token", token);
            }
        }

        // API key invalid or missing - return 401
        throw new UnauthorizedException("Invalid API key");
    }
}
