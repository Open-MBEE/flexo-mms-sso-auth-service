package org.openmbee.flexo.mms.sso.oauth;

import java.net.URI;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * A client allowed to use the authorization endpoint: either configured or resolved from a
 * Client ID Metadata Document. Public clients have no secret and must use PKCE.
 */
public record OAuthClient(String clientId, String encodedSecret, String name, List<String> redirectUris,
                          boolean trusted, boolean metadataDocument) {

    private static final Set<String> LOOPBACK_HOSTS = Set.of("localhost", "127.0.0.1", "[::1]");

    public boolean isConfidential() {
        return encodedSecret != null && !encodedSecret.isBlank();
    }

    public String displayName() {
        return name != null && !name.isBlank() ? name : clientId;
    }

    /** Exact match, except loopback http redirects may use any port (RFC 8252 section 7.3). */
    public boolean allowsRedirectUri(String requested) {
        if (requested == null || requested.isBlank()) {
            return false;
        }
        for (String registered : redirectUris) {
            if (registered.equals(requested) || loopbackMatch(registered, requested)) {
                return true;
            }
        }
        return false;
    }

    private static boolean loopbackMatch(String registered, String requested) {
        try {
            URI r = URI.create(registered);
            URI q = URI.create(requested);
            return "http".equals(r.getScheme()) && "http".equals(q.getScheme())
                    && r.getHost() != null && LOOPBACK_HOSTS.contains(r.getHost())
                    && r.getHost().equals(q.getHost())
                    && Objects.equals(r.getRawPath(), q.getRawPath())
                    && Objects.equals(r.getRawQuery(), q.getRawQuery())
                    && q.getRawFragment() == null && q.getRawUserInfo() == null;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}
