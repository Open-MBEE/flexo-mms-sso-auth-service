package org.openmbee.flexo.mms.sso.oauth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Resolves OAuth clients whose client_id is an HTTPS URL pointing at a Client ID Metadata Document
 * (draft-ietf-oauth-client-id-metadata-document), as used by MCP clients without pre-registration.
 */
@Component
public class CimdClientResolver {

    private static final Logger log = LoggerFactory.getLogger(CimdClientResolver.class);
    private static final Pattern MAX_AGE = Pattern.compile("max-age=(\\d+)");
    private static final int MAX_CACHE_ENTRIES = 1000;

    private final OAuthServerProperties.Cimd config;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final Map<String, CachedClient> cache = new ConcurrentHashMap<>();
    private final HttpClient httpClient;

    private record CachedClient(OAuthClient client, long expiresAt) {}

    public CimdClientResolver(OAuthServerProperties properties) {
        this.config = properties.getCimd();
        this.httpClient = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofMillis(config.getTimeout()))
                .build();
    }

    public boolean isEnabled() {
        return config.isEnabled();
    }

    public boolean looksLikeMetadataUrl(String clientId) {
        return clientId != null && (clientId.startsWith("https://")
                || (config.isAllowHttp() && clientId.startsWith("http://")));
    }

    public Optional<OAuthClient> resolve(String clientId) {
        if (!config.isEnabled() || !looksLikeMetadataUrl(clientId)) {
            return Optional.empty();
        }

        CachedClient cached = cache.get(clientId);
        if (cached != null && cached.expiresAt() > System.currentTimeMillis()) {
            return Optional.of(cached.client());
        }

        URI uri = validateClientIdUrl(clientId);
        checkAddresses(uri.getHost());

        HttpResponse<InputStream> response;
        try {
            HttpRequest request = HttpRequest.newBuilder(uri)
                    .timeout(Duration.ofMillis(config.getTimeout()))
                    .header("Accept", "application/json")
                    .GET()
                    .build();
            response = httpClient.send(request, HttpResponse.BodyHandlers.ofInputStream());
        } catch (IOException e) {
            log.debug("CIMD fetch failed for {}: {}", clientId, e.getMessage());
            throw invalidClient("client metadata document could not be fetched");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw invalidClient("client metadata document could not be fetched");
        }

        byte[] body;
        try (InputStream in = response.body()) {
            if (response.statusCode() != 200) {
                throw invalidClient("client metadata document returned HTTP " + response.statusCode());
            }
            body = in.readNBytes(config.getMaxBytes() + 1);
        } catch (IOException e) {
            throw invalidClient("client metadata document could not be read");
        }
        if (body.length > config.getMaxBytes()) {
            throw invalidClient("client metadata document exceeds " + config.getMaxBytes() + " bytes");
        }

        OAuthClient client = parse(clientId, body);

        long ttl = cacheTtl(response.headers().firstValue("Cache-Control").orElse(""));
        if (ttl > 0) {
            if (cache.size() >= MAX_CACHE_ENTRIES) {
                cache.clear();
            }
            cache.put(clientId, new CachedClient(client, System.currentTimeMillis() + ttl));
        }
        return Optional.of(client);
    }

    URI validateClientIdUrl(String clientId) {
        URI uri;
        try {
            uri = new URI(clientId);
        } catch (Exception e) {
            throw invalidClient("client_id is not a valid URL");
        }
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        if (!"https".equals(scheme) && !(config.isAllowHttp() && "http".equals(scheme))) {
            throw invalidClient("client_id URL must use https");
        }
        String path = uri.getRawPath();
        if (uri.getHost() == null || uri.getRawUserInfo() != null || uri.getRawFragment() != null
                || path == null || path.isEmpty() || "/".equals(path)
                || path.contains("/./") || path.contains("/../") || path.endsWith("/.") || path.endsWith("/..")) {
            throw invalidClient("client_id URL must have a host and a path, and no credentials or fragment");
        }
        if (!hostAllowed(uri.getHost().toLowerCase(Locale.ROOT))) {
            throw invalidClient("client_id host is not allowed");
        }
        return uri;
    }

    private boolean hostAllowed(String host) {
        List<String> allowed = config.getAllowedHosts();
        if (allowed == null || allowed.isEmpty()) {
            return true;
        }
        for (String entry : allowed) {
            String pattern = entry.trim().toLowerCase(Locale.ROOT);
            if (pattern.startsWith("*.") ? host.endsWith(pattern.substring(1)) : host.equals(pattern)) {
                return true;
            }
        }
        return false;
    }

    private void checkAddresses(String host) {
        if (config.isAllowPrivateAddresses()) {
            return;
        }
        InetAddress[] addresses;
        try {
            addresses = InetAddress.getAllByName(host);
        } catch (UnknownHostException e) {
            throw invalidClient("client_id host could not be resolved");
        }
        for (InetAddress address : addresses) {
            if (isNonPublic(address)) {
                throw invalidClient("client_id host resolves to a non-public address");
            }
        }
    }

    static boolean isNonPublic(InetAddress address) {
        if (address.isLoopbackAddress() || address.isAnyLocalAddress() || address.isLinkLocalAddress()
                || address.isSiteLocalAddress() || address.isMulticastAddress()) {
            return true;
        }
        byte[] b = address.getAddress();
        if (address instanceof Inet6Address) {
            // unique local fc00::/7
            return (b[0] & 0xfe) == 0xfc;
        }
        // carrier-grade NAT 100.64.0.0/10 and 0.0.0.0/8
        return ((b[0] & 0xff) == 100 && (b[1] & 0xc0) == 64) || (b[0] & 0xff) == 0;
    }

    private OAuthClient parse(String clientId, byte[] body) {
        JsonNode doc;
        try {
            doc = objectMapper.readTree(body);
        } catch (IOException e) {
            throw invalidClient("client metadata document is not valid JSON");
        }
        if (doc == null || !doc.isObject()) {
            throw invalidClient("client metadata document must be a JSON object");
        }
        if (!clientId.equals(doc.path("client_id").asText(null))) {
            throw invalidClient("client metadata document client_id does not match its URL");
        }

        String authMethod = doc.path("token_endpoint_auth_method").asText("none");
        if (!"none".equals(authMethod)) {
            throw invalidClient("only public clients (token_endpoint_auth_method=none) are supported via metadata documents");
        }
        if (doc.has("client_secret") || doc.has("client_secret_expires_at")) {
            throw invalidClient("client metadata document must not contain a client_secret");
        }
        requireContains(doc, "grant_types", "authorization_code");
        requireContains(doc, "response_types", "code");

        List<String> redirectUris = new ArrayList<>();
        JsonNode uris = doc.path("redirect_uris");
        if (!uris.isArray() || uris.isEmpty()) {
            throw invalidClient("client metadata document must list redirect_uris");
        }
        for (JsonNode uri : uris) {
            if (!uri.isTextual() || !isAcceptableRedirectUri(uri.asText())) {
                throw invalidClient("client metadata document has an invalid redirect_uri");
            }
            redirectUris.add(uri.asText());
        }

        String name = doc.path("client_name").asText(null);
        return new OAuthClient(clientId, null, name, List.copyOf(redirectUris), false, true);
    }

    private static void requireContains(JsonNode doc, String field, String value) {
        JsonNode node = doc.get(field);
        if (node == null) {
            return;
        }
        if (!node.isArray()) {
            throw invalidClient("client metadata " + field + " must be an array");
        }
        for (JsonNode item : node) {
            if (value.equals(item.asText())) {
                return;
            }
        }
        throw invalidClient("client metadata " + field + " must include " + value);
    }

    /** https, http on loopback, or a private-use scheme; never javascript/data/file. */
    static boolean isAcceptableRedirectUri(String value) {
        URI uri;
        try {
            uri = new URI(value);
        } catch (Exception e) {
            return false;
        }
        String scheme = uri.getScheme();
        if (scheme == null || uri.getRawFragment() != null) {
            return false;
        }
        scheme = scheme.toLowerCase(Locale.ROOT);
        return switch (scheme) {
            case "https" -> uri.getHost() != null;
            case "http" -> uri.getHost() != null
                    && List.of("localhost", "127.0.0.1", "[::1]").contains(uri.getHost());
            case "javascript", "data", "file", "vbscript", "about", "blob" -> false;
            default -> true;
        };
    }

    private long cacheTtl(String cacheControl) {
        String value = cacheControl.toLowerCase(Locale.ROOT);
        if (value.contains("no-store") || value.contains("no-cache")) {
            return 0;
        }
        Matcher m = MAX_AGE.matcher(value);
        if (m.find()) {
            try {
                return Math.min(Long.parseLong(m.group(1)) * 1000, config.getCacheTtl());
            } catch (NumberFormatException e) {
                return config.getCacheTtl();
            }
        }
        return config.getCacheTtl();
    }

    private static OAuthException invalidClient(String description) {
        return new OAuthException(HttpStatus.BAD_REQUEST, "invalid_client", description);
    }
}
