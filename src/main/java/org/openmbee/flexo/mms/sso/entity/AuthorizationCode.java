package org.openmbee.flexo.mms.sso.entity;

import jakarta.persistence.*;

import java.time.LocalDateTime;

/**
 * Short-lived, single-use OAuth authorization code. Only the SHA-256 hash of the code is stored.
 * chainId records the refresh chain issued on redemption so a replayed code can revoke it.
 */
@Entity
@Table(name = "oauth_authorization_codes", indexes = {
        @Index(name = "idx_oauth_code_hash", columnList = "codeHash", unique = true)
})
public class AuthorizationCode {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String codeHash;

    @Column(nullable = false, length = 2048)
    private String clientId;

    @Column(nullable = false, length = 2048)
    private String redirectUri;

    @Column(nullable = false)
    private String codeChallenge;

    @Column(nullable = false, length = 2048)
    private String resource;

    @Column(length = 1024)
    private String scope;

    @Column(nullable = false)
    private String userId;

    @Column(nullable = false)
    private LocalDateTime expiresAt;

    @Column(nullable = false)
    private boolean used = false;

    private String chainId;

    private LocalDateTime createdAt = LocalDateTime.now();

    public AuthorizationCode() {
    }

    public AuthorizationCode(String codeHash, String clientId, String redirectUri, String codeChallenge,
                             String resource, String scope, String userId, LocalDateTime expiresAt) {
        this.codeHash = codeHash;
        this.clientId = clientId;
        this.redirectUri = redirectUri;
        this.codeChallenge = codeChallenge;
        this.resource = resource;
        this.scope = scope;
        this.userId = userId;
        this.expiresAt = expiresAt;
    }

    public boolean isExpired() {
        return LocalDateTime.now().isAfter(expiresAt);
    }

    public Long getId() { return id; }
    public String getCodeHash() { return codeHash; }
    public String getClientId() { return clientId; }
    public String getRedirectUri() { return redirectUri; }
    public String getCodeChallenge() { return codeChallenge; }
    public String getResource() { return resource; }
    public String getScope() { return scope; }
    public String getUserId() { return userId; }
    public LocalDateTime getExpiresAt() { return expiresAt; }
    public boolean isUsed() { return used; }
    public void setUsed(boolean used) { this.used = used; }
    public String getChainId() { return chainId; }
    public void setChainId(String chainId) { this.chainId = chainId; }
    public LocalDateTime getCreatedAt() { return createdAt; }
}
