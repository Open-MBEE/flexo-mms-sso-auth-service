package org.openmbee.flexo.mms.sso.controller;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.openmbee.flexo.mms.sso.entity.ApiKey;
import org.openmbee.flexo.mms.sso.exception.UnauthorizedException;
import org.openmbee.flexo.mms.sso.service.ApiKeyService;
import org.openmbee.flexo.mms.sso.service.SparqlUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@RestController
public class ApiKeyAuthController {

    private final ApiKeyService apiKeyService;
    private final SparqlUserService sparqlUserService;

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri:http://localhost:8080}")
    private String issuerUri;

    @Value("${jwt.audience:flexo-mms-api}")
    private String jwtAudience;

    @Value("${jwt.secret:flexo-mms-secret}")
    private String jwtSecret;

    @Autowired
    public ApiKeyAuthController(ApiKeyService apiKeyService, SparqlUserService sparqlUserService) {
        this.apiKeyService = apiKeyService;
        this.sparqlUserService = sparqlUserService;
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
                String username = key.getUserId(); // Using userId as username
                
                // Get all available groups from SPARQL
                List<String> availableGroups = sparqlUserService.getUserGroups(username);
                
                // Generate JWT token with username
                String token = generateJWT(username, availableGroups);
                
                // Return in same format as flexo-mms-auth-service
                return Collections.singletonMap("token", token);
            }
        }
        
        // API key invalid or missing - return 401
        throw new UnauthorizedException("Invalid API key");
    }
    
    private String generateJWT(String username, List<String> groups) {
        Date expires = new Date(System.currentTimeMillis() + (1 * 24 * 60 * 60 * 1000)); // 1 day
        
        return JWT.create()
            .withAudience(jwtAudience)
            .withIssuer(issuerUri)
            .withClaim("username", username)
            .withClaim("groups", groups)
            .withExpiresAt(expires)
            .sign(Algorithm.HMAC256(jwtSecret));
    }
}