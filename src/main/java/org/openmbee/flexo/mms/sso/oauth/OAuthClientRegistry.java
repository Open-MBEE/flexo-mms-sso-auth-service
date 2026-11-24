package org.openmbee.flexo.mms.sso.oauth;

import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Looks up OAuth clients (configured first, then Client ID Metadata Documents) and authenticates
 * them at the token and revocation endpoints. Dynamic client registration is not supported.
 */
@Component
public class OAuthClientRegistry {

    private final Map<String, OAuthClient> configured = new LinkedHashMap<>();
    private final CimdClientResolver cimdResolver;
    private final PasswordEncoder passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();

    public OAuthClientRegistry(OAuthServerProperties properties, CimdClientResolver cimdResolver) {
        this.cimdResolver = cimdResolver;
        for (OAuthServerProperties.Client c : properties.getClients()) {
            if (c.getClientId() == null || c.getClientId().isBlank()) {
                throw new IllegalStateException("OAuth client entries require a client_id");
            }
            String secret = c.getClientSecret();
            if (secret != null && !secret.isBlank() && !secret.startsWith("{")) {
                throw new IllegalStateException("client_secret for OAuth client '" + c.getClientId()
                        + "' must be encoded with an {id} prefix, e.g. {bcrypt}... or {noop}...");
            }
            for (String uri : c.getRedirectUris()) {
                if (!CimdClientResolver.isAcceptableRedirectUri(uri)) {
                    throw new IllegalStateException("invalid redirect_uri '" + uri + "' for OAuth client '" + c.getClientId() + "'");
                }
            }
            configured.put(c.getClientId(), new OAuthClient(c.getClientId(), secret, c.getName(),
                    List.copyOf(c.getRedirectUris()), c.isTrusted(), false));
        }
    }

    public boolean isCimdEnabled() {
        return cimdResolver.isEnabled();
    }

    public Optional<OAuthClient> find(String clientId) {
        if (clientId == null || clientId.isBlank()) {
            return Optional.empty();
        }
        OAuthClient client = configured.get(clientId);
        if (client != null) {
            return Optional.of(client);
        }
        return cimdResolver.resolve(clientId);
    }

    /**
     * Authenticates the client of a token/revocation request via client_secret_basic,
     * client_secret_post, or (public clients) client_id alone.
     */
    public OAuthClient authenticate(String authorizationHeader, Map<String, String> form) {
        String clientId = form.get("client_id");
        String secret = form.get("client_secret");

        if (authorizationHeader != null && authorizationHeader.regionMatches(true, 0, "Basic ", 0, 6)) {
            String[] parts = decodeBasic(authorizationHeader.substring(6).trim());
            if (clientId != null && !clientId.equals(parts[0])) {
                throw OAuthException.invalidClient("client_id does not match Authorization header");
            }
            clientId = parts[0];
            secret = parts[1];
        }

        if (clientId == null || clientId.isBlank()) {
            throw OAuthException.invalidClient("client authentication required");
        }

        OAuthClient client;
        try {
            client = find(clientId).orElseThrow(() -> OAuthException.invalidClient("unknown client"));
        } catch (OAuthException e) {
            throw OAuthException.invalidClient(e.getMessage());
        }

        if (client.isConfidential()) {
            if (secret == null || !passwordEncoder.matches(secret, client.encodedSecret())) {
                throw OAuthException.invalidClient("client authentication failed");
            }
        } else if (secret != null && !secret.isEmpty()) {
            throw OAuthException.invalidClient("public client must not send a client_secret");
        }
        return client;
    }

    private static String[] decodeBasic(String encoded) {
        try {
            String decoded = new String(Base64.getDecoder().decode(encoded), StandardCharsets.UTF_8);
            int colon = decoded.indexOf(':');
            if (colon < 0) {
                throw OAuthException.invalidClient("malformed Basic credentials");
            }
            // RFC 6749 section 2.3.1: id and secret are form-urlencoded before Basic encoding
            return new String[]{
                    URLDecoder.decode(decoded.substring(0, colon), StandardCharsets.UTF_8),
                    URLDecoder.decode(decoded.substring(colon + 1), StandardCharsets.UTF_8)
            };
        } catch (IllegalArgumentException e) {
            throw OAuthException.invalidClient("malformed Basic credentials");
        }
    }
}
