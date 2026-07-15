package org.openmbee.flexo.mms.sso.controller;

import org.openmbee.flexo.mms.sso.service.TokenSigner;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Publishes the JWK Set for verifying RS256-signed layer1 tokens.
 * Returns an empty key set while signing with the legacy HS256 shared secret.
 */
@RestController
public class JwksController {

    private final TokenSigner tokenSigner;

    public JwksController(TokenSigner tokenSigner) {
        this.tokenSigner = tokenSigner;
    }

    @GetMapping("/.well-known/jwks.json")
    public Map<String, Object> jwks() {
        return tokenSigner.jwks();
    }
}
