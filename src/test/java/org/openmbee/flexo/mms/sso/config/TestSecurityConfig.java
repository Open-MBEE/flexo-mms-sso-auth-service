package org.openmbee.flexo.mms.sso.config;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

import java.util.Collections;

@TestConfiguration
@Profile("test")
public class TestSecurityConfig {

    @Bean
    @Primary
    public ClientRegistrationRepository clientRegistrationRepository() {
        return new InMemoryClientRegistrationRepository(Collections.singletonList(
            ClientRegistration.withRegistrationId("oidc")
                .clientId("test-client-id")
                .clientSecret("test-client-secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("http://localhost:8080/login/oauth2/code/oidc")
                .scope("openid", "profile", "email")
                .authorizationUri("http://localhost:8080/oauth/authorize")
                .tokenUri("http://localhost:8080/oauth/token")
                .jwkSetUri("http://localhost:8080/oauth/jwks")
                .userInfoUri("http://localhost:8080/oauth/userinfo")
                .userNameAttributeName("sub")
                .clientName("OIDC Test Client")
                .build()
        ));
    }

    // note: no JwtDecoder bean here — tests @MockBean it, which replaces the
    // one declared by SecurityConfig (a second definition under the same bean
    // name would fail context startup with bean-definition overriding disabled)
}