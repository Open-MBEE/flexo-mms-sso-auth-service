package org.openmbee.flexo.mms.sso.service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.openmbee.flexo.mms.sso.entity.ApiKey;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    @Mock
    private ApiKeyService apiKeyService;

    @InjectMocks
    private UserService userService;

    @Test
    void getUserGroups_withOidcUserAndGroups_returnsSsoGroups() {
        // Ensure the default group claims field is used
        ReflectionTestUtils.setField(userService, "groupClaimsField", "groups");
        
        // Prepare test data
        String username = "testuser";
        List<String> expectedGroups = List.of("group1", "group2", "admin");
        
        // Create claims with groups
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", username);
        claims.put("groups", expectedGroups);
        
        // Create an OidcUser
        OidcIdToken idToken = new OidcIdToken("token", Instant.now(), 
                Instant.now().plusSeconds(3600), claims);
        OidcUser oidcUser = new DefaultOidcUser(Collections.emptyList(), idToken);
        
        // Create authentication with OidcUser as principal
        Authentication authentication = new TestingAuthenticationToken(oidcUser, null);
        
        // Set the authentication in SecurityContextHolder
        SecurityContextHolder.getContext().setAuthentication(authentication);
        
        // Call the method
        List<String> actualGroups = userService.getUserGroups(username);
        
        // Verify the results
        assertEquals(expectedGroups, actualGroups);
        
        // Clean up
        SecurityContextHolder.clearContext();
    }

    @Test
    void getUserGroups_withNoOidcUser_returnsNull() {
        // Ensure the default group claims field is used
        ReflectionTestUtils.setField(userService, "groupClaimsField", "groups");
        
        // Prepare test data
        String username = "testuser";
        
        // Call the method without setting an authentication in SecurityContextHolder
        List<String> actualGroups = userService.getUserGroups(username);
        
        // Verify the results - now returns null since there's no SPARQL fallback
        assertNull(actualGroups);
    }

    @Test
    void getUserGroups_withOidcUserButNoGroups_returnsNull() {
        // Ensure the default group claims field is used
        ReflectionTestUtils.setField(userService, "groupClaimsField", "groups");
        
        // Prepare test data
        String username = "testuser";
        
        // Create claims without groups
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", username);
        
        // Create an OidcUser
        OidcIdToken idToken = new OidcIdToken("token", Instant.now(), 
                Instant.now().plusSeconds(3600), claims);
        OidcUser oidcUser = new DefaultOidcUser(Collections.emptyList(), idToken);
        
        // Create authentication with OidcUser as principal
        Authentication authentication = new TestingAuthenticationToken(oidcUser, null);
        
        // Set the authentication in SecurityContextHolder
        SecurityContextHolder.getContext().setAuthentication(authentication);
        
        // Call the method
        List<String> actualGroups = userService.getUserGroups(username);
        
        // Verify the results - now returns null since there's no SPARQL fallback
        assertNull(actualGroups);
        
        // Clean up
        SecurityContextHolder.clearContext();
    }
    
    @Test
    void getUserGroups_withCustomGroupClaimsField_usesConfiguredField() {
        // Set a custom group claims field
        ReflectionTestUtils.setField(userService, "groupClaimsField", "memberOf");
        
        // Prepare test data
        String username = "testuser";
        List<String> expectedGroups = List.of("group1", "group2", "admin");
        
        // Create claims with groups using the custom field
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", username);
        claims.put("memberOf", expectedGroups);
        
        // Create an OidcUser
        OidcIdToken idToken = new OidcIdToken("token", Instant.now(), 
                Instant.now().plusSeconds(3600), claims);
        OidcUser oidcUser = new DefaultOidcUser(Collections.emptyList(), idToken);
        
        // Create authentication with OidcUser as principal
        Authentication authentication = new TestingAuthenticationToken(oidcUser, null);
        
        // Set the authentication in SecurityContextHolder
        SecurityContextHolder.getContext().setAuthentication(authentication);
        
        // Call the method
        List<String> actualGroups = userService.getUserGroups(username);
        
        // Verify the results
        assertEquals(expectedGroups, actualGroups);
        
        // Clean up
        SecurityContextHolder.clearContext();
    }
}