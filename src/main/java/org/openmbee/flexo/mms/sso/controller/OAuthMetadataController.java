package org.openmbee.flexo.mms.sso.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.openmbee.flexo.mms.sso.oauth.OAuthClientRegistry;
import org.openmbee.flexo.mms.sso.oauth.OAuthServerProperties;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * OAuth 2.0 Authorization Server Metadata (RFC 8414), also served at the OpenID discovery path
 * because MCP clients probe both.
 */
@RestController
public class OAuthMetadataController {

    private final OAuthServerProperties properties;
    private final OAuthClientRegistry clientRegistry;

    public OAuthMetadataController(OAuthServerProperties properties, OAuthClientRegistry clientRegistry) {
        this.properties = properties;
        this.clientRegistry = clientRegistry;
    }

    @GetMapping({"/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"})
    public ResponseEntity<Map<String, Object>> metadata(HttpServletRequest request) {
        if (!properties.isEnabled()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
        String issuer = properties.resolveIssuer(request);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("issuer", issuer);
        body.put("authorization_endpoint", issuer + "/oauth/authorize");
        body.put("token_endpoint", issuer + "/token");
        body.put("revocation_endpoint", issuer + "/oauth/revoke");
        body.put("jwks_uri", issuer + "/.well-known/jwks.json");
        body.put("response_types_supported", List.of("code"));
        body.put("response_modes_supported", List.of("query"));
        body.put("grant_types_supported", List.of("authorization_code", "refresh_token",
                "urn:ietf:params:oauth:grant-type:token-exchange"));
        body.put("code_challenge_methods_supported", List.of("S256"));
        body.put("token_endpoint_auth_methods_supported", List.of("client_secret_basic", "client_secret_post", "none"));
        body.put("revocation_endpoint_auth_methods_supported", List.of("client_secret_basic", "client_secret_post", "none"));
        body.put("authorization_response_iss_parameter_supported", true);
        body.put("client_id_metadata_document_supported", clientRegistry.isCimdEnabled());
        if (!properties.getScopes().isEmpty()) {
            body.put("scopes_supported", properties.getScopes());
        }

        return ResponseEntity.ok().cacheControl(CacheControl.maxAge(Duration.ofMinutes(5)).cachePublic()).body(body);
    }
}
