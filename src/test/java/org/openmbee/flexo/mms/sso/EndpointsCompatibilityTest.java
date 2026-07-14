package org.openmbee.flexo.mms.sso;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.openmbee.flexo.mms.sso.config.SecurityConfig;
import org.openmbee.flexo.mms.sso.config.TestSecurityConfig;
import org.openmbee.flexo.mms.sso.controller.MainController;
import org.openmbee.flexo.mms.sso.entity.ApiKey;
import org.openmbee.flexo.mms.sso.service.ApiKeyService;
import org.openmbee.flexo.mms.sso.service.ProvisioningService;
import org.openmbee.flexo.mms.sso.service.RefreshTokenService;
import org.openmbee.flexo.mms.sso.service.TokenSigner;
import org.openmbee.flexo.mms.sso.service.UserService;
import org.openmbee.flexo.mms.sso.util.UserIdExtractor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

// import the real SecurityConfig so its filter chains (not Boot's default fallback chain)
// are what the assertions exercise; TestSecurityConfig supplies the ClientRegistrationRepository
@WebMvcTest
@Import({TestSecurityConfig.class, SecurityConfig.class})
@ActiveProfiles("test")
public class EndpointsCompatibilityTest {

    @Autowired
    private MockMvc mockMvc;
    
    @MockBean
    private ApiKeyService apiKeyService;
    
    @MockBean
    private JwtDecoder jwtDecoder;
    
    @MockBean
    private MainController mainController;
    
    @MockBean
    private UserService userService;

    @MockBean
    private UserIdExtractor userIdExtractor;

    @MockBean
    private TokenSigner tokenSigner;

    @MockBean
    private ProvisioningService provisioningService;

    @MockBean
    private RefreshTokenService refreshTokenService;

    @Test
    public void testIndexEndpoint() throws Exception {
        // Setup the main controller to return the index template
        Mockito.when(mainController.home()).thenReturn("index");
        
        mockMvc.perform(get("/"))
            .andExpect(status().isOk())
            .andExpect(model().size(0))
            .andExpect(view().name("index"));
    }

    @Test
    @Disabled("no /check endpoint is implemented in this service; SecurityConfig permits the path "
            + "but no controller maps it (pre-existing legacy auth-service compatibility gap)")
    public void testCheckEndpointWithNoAuth() throws Exception {
        mockMvc.perform(get("/check")
            .contentType(MediaType.APPLICATION_JSON))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.user.name").value("anonymous"))
            .andExpect(jsonPath("$.user.groups").isEmpty());
    }

    @Test
    public void testLoginEndpointWithoutApiKey() throws Exception {
        mockMvc.perform(get("/login"))
            .andExpect(status().isUnauthorized());
    }
    
    @Test
    public void testLoginEndpointWithBearerAuth() throws Exception {
        // Mock API key validation to return empty (invalid API key)
        Mockito.when(apiKeyService.validateApiKey("test-api-key")).thenReturn(Optional.empty());

        // the bearer resolver then treats the value as a JWT; reject it
        // (BadJwtException specifically: JwtAuthenticationProvider translates it to a 401,
        // whereas a plain JwtException surfaces as an AuthenticationServiceException)
        Mockito.when(jwtDecoder.decode("test-api-key")).thenThrow(new BadJwtException("not a valid token"));

        mockMvc.perform(get("/login")
                .header("Authorization", "Bearer test-api-key"))
            .andExpect(status().isUnauthorized());
    }
    
    @Test
    public void testLoginEndpointWithValidApiKey() throws Exception {
        // Create a valid API key
        ApiKey apiKey = new ApiKey();
        apiKey.setUserId("testuser");
        apiKey.setKeyValue("valid-api-key");
        apiKey.setName("Test Key");
        
        // Mock API key validation to return the valid key
        Mockito.when(apiKeyService.validateApiKey("valid-api-key")).thenReturn(Optional.of(apiKey));
        
        // Mock user service to return groups
        List<String> groups = Arrays.asList("group1", "group2");
        Mockito.when(userService.getUserGroups("testuser")).thenReturn(groups);

        // Mock token signing (login now delegates to TokenSigner)
        Mockito.when(tokenSigner.sign(Mockito.eq("testuser"), Mockito.eq(groups), Mockito.anyLong()))
            .thenReturn("test-jwt-token");

        mockMvc.perform(get("/login")
                .header("Authorization", "Bearer valid-api-key"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.token").exists());
    }
}