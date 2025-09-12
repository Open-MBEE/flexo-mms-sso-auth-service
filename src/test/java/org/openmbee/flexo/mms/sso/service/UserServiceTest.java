package org.openmbee.flexo.mms.sso.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.openmbee.flexo.mms.sso.entity.ApiKey;
import org.openmbee.flexo.mms.sso.entity.User;
import org.openmbee.flexo.mms.sso.repository.UserRepository;
import org.openmbee.flexo.mms.sso.util.UserIdExtractor;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    @Mock
    private ApiKeyService apiKeyService;
    
    @Mock
    private UserRepository userRepository;
    
    @Mock
    private UserIdExtractor userIdExtractor;

    @InjectMocks
    private UserService userService;
    
    private User testUser;
    
    @BeforeEach
    void setUp() {
        // Mock the UserIdExtractor for consistent behavior
        lenient().when(userIdExtractor.extractUserIdFromOidcUser(any(OidcUser.class)))
                .thenAnswer(invocation -> {
                    OidcUser oidcUser = invocation.getArgument(0);
                    return oidcUser.getSubject();
                });
        
        lenient().when(userIdExtractor.extractUserId(any(Authentication.class)))
                .thenAnswer(invocation -> {
                    Authentication auth = invocation.getArgument(0);
                    if (auth.getPrincipal() instanceof OidcUser) {
                        return ((OidcUser) auth.getPrincipal()).getSubject();
                    }
                    return auth.getName();
                });
        testUser = new User();
        testUser.setUserId("testuser");
        testUser.setName("Test User");
        testUser.setEmail("test@example.com");
        testUser.setGroups(Arrays.asList("group1", "group2", "admin"));
        testUser.setCreatedAt(LocalDateTime.now().minusDays(10));
        testUser.setLastLoginAt(LocalDateTime.now().minusDays(1));
    }

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
        
        // Set up mock to return empty for database lookup
        when(userRepository.findByUserId(username)).thenReturn(Optional.empty());
        
        // Call the method
        List<String> actualGroups = userService.getUserGroups(username);
        
        // Verify the results
        assertEquals(expectedGroups, actualGroups);
        
        // Clean up
        SecurityContextHolder.clearContext();
    }

    @Test
    void getUserGroups_withNoOidcUser_returnsEmptyList() {
        // Ensure the default group claims field is used
        ReflectionTestUtils.setField(userService, "groupClaimsField", "groups");
        
        // Prepare test data
        String username = "testuser";
        
        // Set up mock to return empty for database lookup
        when(userRepository.findByUserId(username)).thenReturn(Optional.empty());
        
        // Call the method without setting an authentication in SecurityContextHolder
        List<String> actualGroups = userService.getUserGroups(username);
        
        // Verify the results - now returns empty list since there's no authentication
        assertTrue(actualGroups.isEmpty());
    }

    @Test
    void getUserGroups_withOidcUserButNoGroups_returnsEmptyList() {
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
        
        // Set up mock to return empty for database lookup
        when(userRepository.findByUserId(username)).thenReturn(Optional.empty());
        
        // Call the method
        List<String> actualGroups = userService.getUserGroups(username);
        
        // Verify the results - now returns empty list since there are no groups
        assertTrue(actualGroups.isEmpty());
        
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
        
        // Set up mock to return empty for database lookup
        when(userRepository.findByUserId(username)).thenReturn(Optional.empty());
        
        // Call the method
        List<String> actualGroups = userService.getUserGroups(username);
        
        // Verify the results
        assertEquals(expectedGroups, actualGroups);
        
        // Clean up
        SecurityContextHolder.clearContext();
    }
    
    @Test
    void getUserGroups_withUserInDatabase_returnsStoredGroups() {
        // Given
        String username = "testuser";
        when(userRepository.findByUserId(username)).thenReturn(Optional.of(testUser));
        
        // When
        List<String> actualGroups = userService.getUserGroups(username);
        
        // Then
        verify(userRepository).findByUserId(username);
        assertEquals(3, actualGroups.size());
        assertTrue(actualGroups.containsAll(Arrays.asList("group1", "group2", "admin")));
    }
    
    @Test
    void saveOrUpdateUser_withNewUser_createsUser() {
        // Given
        String userId = "newuser";
        String name = "New User";
        String email = "new@example.com";
        List<String> groups = Arrays.asList("group1", "group2");
        
        when(userRepository.findByUserId(userId)).thenReturn(Optional.empty());
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));
        
        // When
        User result = userService.saveOrUpdateUser(userId, name, email, groups);
        
        // Then
        verify(userRepository).findByUserId(userId);
        verify(userRepository).save(any(User.class));
        
        assertEquals(userId, result.getUserId());
        assertEquals(name, result.getName());
        assertEquals(email, result.getEmail());
        assertEquals(groups, result.getGroups());
        assertNotNull(result.getLastLoginAt());
        assertNotNull(result.getCreatedAt());
    }
    
    @Test
    void saveOrUpdateUser_withExistingUser_updatesUser() {
        // Given
        String userId = "testuser";
        String name = "Updated User";
        String email = "updated@example.com";
        List<String> groups = Arrays.asList("newgroup");
        
        when(userRepository.findByUserId(userId)).thenReturn(Optional.of(testUser));
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));
        
        // When
        User result = userService.saveOrUpdateUser(userId, name, email, groups);
        
        // Then
        verify(userRepository).findByUserId(userId);
        verify(userRepository).save(any(User.class));
        
        assertEquals(userId, result.getUserId());
        assertEquals(name, result.getName());
        assertEquals(email, result.getEmail());
        assertEquals(groups, result.getGroups());
    }
    
    @Test
    void getUserDetails_withOidcUser_storesUserInDatabase() {
        // Given
        String userId = "testuser";
        String name = "Test User";
        String email = "test@example.com";
        List<String> groups = Arrays.asList("group1", "group2");
        
        // Create claims with groups
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", userId);
        claims.put("name", name);
        claims.put("email", email);
        claims.put("groups", groups);
        
        // Just need to set the groupClaimsField since userIdField is handled by the UserIdExtractor mock
        ReflectionTestUtils.setField(userService, "groupClaimsField", "groups");
        
        // Create an OidcUser
        OidcIdToken idToken = new OidcIdToken("token", Instant.now(), 
                Instant.now().plusSeconds(3600), claims);
        OidcUserInfo userInfo = new OidcUserInfo(claims);
        OidcUser oidcUser = new DefaultOidcUser(Collections.emptyList(), idToken, userInfo);
        
        // Create authentication with OidcUser as principal
        Authentication authentication = new TestingAuthenticationToken(oidcUser, null);
        
        when(userRepository.findByUserId(userId)).thenReturn(Optional.empty());
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(apiKeyService.getApiKeysForUser(userId)).thenReturn(Collections.emptyList());
        
        // When
        Map<String, Object> result = userService.getUserDetails(authentication);
        
        // Then
        verify(userRepository).save(any(User.class));
        
        assertEquals(userId, result.get("userId"));
        assertEquals(name, result.get("name"));
        assertEquals(email, result.get("email"));
        assertEquals(groups, result.get("groups"));
    }
}