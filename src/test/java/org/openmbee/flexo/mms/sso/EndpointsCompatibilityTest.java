package org.openmbee.flexo.mms.sso;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.openmbee.flexo.mms.sso.config.TestSecurityConfig;
import org.openmbee.flexo.mms.sso.controller.MainController;
import org.openmbee.flexo.mms.sso.service.ApiKeyService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Optional;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest
@Import(TestSecurityConfig.class)
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
        
        mockMvc.perform(get("/login")
                .header("Authorization", "Bearer test-api-key"))
            .andExpect(status().isUnauthorized());
    }
}