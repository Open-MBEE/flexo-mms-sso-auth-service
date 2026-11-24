package org.openmbee.flexo.mms.sso.oauth;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.util.ArrayList;
import java.util.List;

/**
 * Settings for the OAuth 2.1 authorization server used by MCP clients
 * (authorization code + PKCE, known clients and optional Client ID Metadata Documents).
 */
@ConfigurationProperties(prefix = "flexo.sso-auth-service.oauth")
public class OAuthServerProperties {

    private boolean enabled = true;

    /** Public issuer URL of this service including context path; derived from the request when empty. */
    private String issuer = "";

    /** Protected resources (MCP server URLs) tokens may be issued for (RFC 8707). */
    private List<String> resources = new ArrayList<>();

    /** Scopes advertised and accepted; empty accepts any requested scope. */
    private List<String> scopes = new ArrayList<>();

    private long accessDuration = 3600000;
    private long refreshDuration = 86400000;
    private long refreshAbsoluteDuration = 604800000;
    private long codeDuration = 60000;

    /** Show the consent page even for trusted clients. */
    private boolean alwaysConsent = false;

    private List<Client> clients = new ArrayList<>();
    private Cimd cimd = new Cimd();

    public String resolveIssuer(HttpServletRequest request) {
        if (issuer != null && !issuer.isBlank()) {
            return stripTrailingSlash(issuer);
        }
        return stripTrailingSlash(ServletUriComponentsBuilder.fromContextPath(request).build().toUriString());
    }

    public static String stripTrailingSlash(String value) {
        return value.endsWith("/") ? value.substring(0, value.length() - 1) : value;
    }

    public static class Client {
        private String clientId;
        /** Encoded secret with a {id} prefix (e.g. {bcrypt}..., {noop}...); empty for public clients. */
        private String clientSecret;
        private String name;
        private List<String> redirectUris = new ArrayList<>();
        /** Skip the consent page for this client. */
        private boolean trusted = false;

        public String getClientId() { return clientId; }
        public void setClientId(String clientId) { this.clientId = clientId; }
        public String getClientSecret() { return clientSecret; }
        public void setClientSecret(String clientSecret) { this.clientSecret = clientSecret; }
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        public List<String> getRedirectUris() { return redirectUris; }
        public void setRedirectUris(List<String> redirectUris) { this.redirectUris = redirectUris; }
        public boolean isTrusted() { return trusted; }
        public void setTrusted(boolean trusted) { this.trusted = trusted; }
    }

    public static class Cimd {
        private boolean enabled = false;
        /** Hosts allowed to serve metadata documents; "*.example.com" matches subdomains. Empty allows any public host. */
        private List<String> allowedHosts = new ArrayList<>();
        /** Development only: accept http:// client ids. */
        private boolean allowHttp = false;
        /** Development only: allow fetching from loopback/private addresses. */
        private boolean allowPrivateAddresses = false;
        private int maxBytes = 5120;
        private long timeout = 5000;
        private long cacheTtl = 300000;

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public List<String> getAllowedHosts() { return allowedHosts; }
        public void setAllowedHosts(List<String> allowedHosts) { this.allowedHosts = allowedHosts; }
        public boolean isAllowHttp() { return allowHttp; }
        public void setAllowHttp(boolean allowHttp) { this.allowHttp = allowHttp; }
        public boolean isAllowPrivateAddresses() { return allowPrivateAddresses; }
        public void setAllowPrivateAddresses(boolean allowPrivateAddresses) { this.allowPrivateAddresses = allowPrivateAddresses; }
        public int getMaxBytes() { return maxBytes; }
        public void setMaxBytes(int maxBytes) { this.maxBytes = maxBytes; }
        public long getTimeout() { return timeout; }
        public void setTimeout(long timeout) { this.timeout = timeout; }
        public long getCacheTtl() { return cacheTtl; }
        public void setCacheTtl(long cacheTtl) { this.cacheTtl = cacheTtl; }
    }

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    public String getIssuer() { return issuer; }
    public void setIssuer(String issuer) { this.issuer = issuer; }
    public List<String> getResources() { return resources; }
    public void setResources(List<String> resources) { this.resources = resources; }
    public List<String> getScopes() { return scopes; }
    public void setScopes(List<String> scopes) { this.scopes = scopes; }
    public long getAccessDuration() { return accessDuration; }
    public void setAccessDuration(long accessDuration) { this.accessDuration = accessDuration; }
    public long getRefreshDuration() { return refreshDuration; }
    public void setRefreshDuration(long refreshDuration) { this.refreshDuration = refreshDuration; }
    public long getRefreshAbsoluteDuration() { return refreshAbsoluteDuration; }
    public void setRefreshAbsoluteDuration(long refreshAbsoluteDuration) { this.refreshAbsoluteDuration = refreshAbsoluteDuration; }
    public long getCodeDuration() { return codeDuration; }
    public void setCodeDuration(long codeDuration) { this.codeDuration = codeDuration; }
    public boolean isAlwaysConsent() { return alwaysConsent; }
    public void setAlwaysConsent(boolean alwaysConsent) { this.alwaysConsent = alwaysConsent; }
    public List<Client> getClients() { return clients; }
    public void setClients(List<Client> clients) { this.clients = clients; }
    public Cimd getCimd() { return cimd; }
    public void setCimd(Cimd cimd) { this.cimd = cimd; }
}
