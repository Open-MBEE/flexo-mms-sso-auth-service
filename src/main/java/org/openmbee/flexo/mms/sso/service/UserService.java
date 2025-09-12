package org.openmbee.flexo.mms.sso.service;

import org.openmbee.flexo.mms.sso.entity.ApiKey;
import org.openmbee.flexo.mms.sso.entity.User;
import org.openmbee.flexo.mms.sso.repository.UserRepository;
import org.openmbee.flexo.mms.sso.util.UserIdExtractor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
public class UserService {

    private final ApiKeyService apiKeyService;
    private final UserRepository userRepository;
    private final UserIdExtractor userIdExtractor;

    @Value("${flexo.sso-auth-service.group_claims_field:groups}")
    private String groupClaimsField;

    @Autowired
    public UserService(ApiKeyService apiKeyService, UserRepository userRepository, UserIdExtractor userIdExtractor) {
        this.apiKeyService = apiKeyService;
        this.userRepository = userRepository;
        this.userIdExtractor = userIdExtractor;
    }

    @Transactional
    public Map<String, Object> getUserDetails(Authentication authentication) {
        Map<String, Object> userDetails = new HashMap<>();

        String userId = null;
        String name = null;
        String email = null;
        List<String> groups = new ArrayList<>();
        Map<String, Object> claims = null;

        if (authentication.getPrincipal() instanceof OidcUser) {
            OidcUser oidcUser = (OidcUser) authentication.getPrincipal();
            userId = userIdExtractor.extractUserIdFromOidcUser(oidcUser);
            name = oidcUser.getFullName();
            email = oidcUser.getEmail();
            claims = oidcUser.getClaims();
            
            // Get groups from claims if available
            if (claims.containsKey(groupClaimsField) && claims.get(groupClaimsField) instanceof List) {
                @SuppressWarnings("unchecked")
                List<String> claimsGroups = (List<String>) claims.get(groupClaimsField);
                groups = new ArrayList<>(claimsGroups);
            }
            
            // Store or update user information in database
            saveOrUpdateUser(userId, name, email, groups);
        } else {
            userId = authentication.getName();
            name = userId;
            
            // Try to get user from database
            Optional<User> userOpt = userRepository.findByUserId(userId);
            if (userOpt.isPresent()) {
                User user = userOpt.get();
                name = user.getName() != null ? user.getName() : userId;
                email = user.getEmail();
                groups = user.getGroups();
            }
        }

        // Get API keys for user
        List<ApiKey> apiKeys = apiKeyService.getApiKeysForUser(userId);
        
        // Build response
        userDetails.put("name", name);
        if (email != null) {
            userDetails.put("email", email);
        }
        if (claims != null) {
            userDetails.put("claims", claims);
        }
        userDetails.put("apiKeys", apiKeys);
        userDetails.put("userId", userId);
        userDetails.put("groups", groups);

        return userDetails;
    }
    
    /**
     * Get user groups from database or SSO claims if not in database
     * 
     * @param username The username of the user
     * @return A list of group identifiers
     */
    @Transactional(readOnly = true)
    public List<String> getUserGroups(String username) {
        // First, check the database for the user and their groups
        Optional<User> userOpt = userRepository.findByUserId(username);
        if (userOpt.isPresent()) {
            User user = userOpt.get();
            List<String> userGroups = user.getGroups();
            if (userGroups != null && !userGroups.isEmpty()) {
                return new ArrayList<>(userGroups);
            }
        }
        
        // If not found in database or no groups, check for a current SSO session
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
                    
                    // If we found the user in database, but with no groups, update them
                    if (userOpt.isPresent() && !groups.isEmpty()) {
                        User user = userOpt.get();
                        user.setGroups(new ArrayList<>(groups));
                        userRepository.save(user);
                    }
                    
                    return groups;
                }
            }
        }
        
        // If no groups found in database or SSO claims, return empty list
        return new ArrayList<>();
    }
    
    /**
     * Saves or updates a user in the database with their group information
     * 
     * @param userId The user ID
     * @param name The user's name
     * @param email The user's email
     * @param groups The user's groups
     * @return The saved User entity
     */
    @Transactional
    public User saveOrUpdateUser(String userId, String name, String email, List<String> groups) {
        User user;
        Optional<User> existingUser = userRepository.findByUserId(userId);
        
        if (existingUser.isPresent()) {
            user = existingUser.get();
            user.setLastLoginAt(LocalDateTime.now());
            
            // Update fields only if they are not null
            if (name != null) {
                user.setName(name);
            }
            
            if (email != null) {
                user.setEmail(email);
            }
            
            // Update groups if provided and different
            if (groups != null && !groups.isEmpty()) {
                user.setGroups(new ArrayList<>(groups));
            }
        } else {
            user = new User(userId, name, email);
            user.setLastLoginAt(LocalDateTime.now());
            
            if (groups != null) {
                user.setGroups(new ArrayList<>(groups));
            }
        }
        
        return userRepository.save(user);
    }
}