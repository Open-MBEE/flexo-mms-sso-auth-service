package org.openmbee.flexo.mms.sso.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.Objects;

/**
 * Rotating refresh token. Only the SHA-256 hash of the token value is persisted.
 * Tokens form a chain (chainId): each rotation revokes the presented token and issues a successor
 * sharing the same chain and absolute expiry. Presenting an already-revoked token revokes the
 * entire chain (reuse detection).
 */
@Entity
@Table(name = "refresh_tokens", indexes = {
        @Index(name = "idx_refresh_token_hash", columnList = "tokenHash", unique = true),
        @Index(name = "idx_refresh_chain", columnList = "chainId")
})
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String userId;

    @Column(nullable = false, unique = true)
    private String tokenHash;

    @Column(nullable = false)
    private String chainId;

    /** Rotation window: token must be used (rotated) before this. */
    @Column(nullable = false)
    private LocalDateTime expiresAt;

    /** Hard cap for the whole chain; successors never extend past this. */
    @Column(nullable = false)
    private LocalDateTime absoluteExpiresAt;

    @Column(nullable = false)
    private boolean revoked = false;

    private LocalDateTime createdAt;

    public RefreshToken() {
        this.createdAt = LocalDateTime.now();
    }

    public RefreshToken(String userId, String tokenHash, String chainId,
                        LocalDateTime expiresAt, LocalDateTime absoluteExpiresAt) {
        this.userId = userId;
        this.tokenHash = tokenHash;
        this.chainId = chainId;
        this.expiresAt = expiresAt;
        this.absoluteExpiresAt = absoluteExpiresAt;
        this.createdAt = LocalDateTime.now();
    }

    public boolean isExpired() {
        LocalDateTime now = LocalDateTime.now();
        return now.isAfter(expiresAt) || now.isAfter(absoluteExpiresAt);
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getTokenHash() {
        return tokenHash;
    }

    public void setTokenHash(String tokenHash) {
        this.tokenHash = tokenHash;
    }

    public String getChainId() {
        return chainId;
    }

    public void setChainId(String chainId) {
        this.chainId = chainId;
    }

    public LocalDateTime getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(LocalDateTime expiresAt) {
        this.expiresAt = expiresAt;
    }

    public LocalDateTime getAbsoluteExpiresAt() {
        return absoluteExpiresAt;
    }

    public void setAbsoluteExpiresAt(LocalDateTime absoluteExpiresAt) {
        this.absoluteExpiresAt = absoluteExpiresAt;
    }

    public boolean isRevoked() {
        return revoked;
    }

    public void setRevoked(boolean revoked) {
        this.revoked = revoked;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RefreshToken that = (RefreshToken) o;
        return Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}
