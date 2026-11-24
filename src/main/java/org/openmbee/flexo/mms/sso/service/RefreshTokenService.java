package org.openmbee.flexo.mms.sso.service;

import org.openmbee.flexo.mms.sso.entity.RefreshToken;
import org.openmbee.flexo.mms.sso.exception.UnauthorizedException;
import org.openmbee.flexo.mms.sso.repository.RefreshTokenRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import org.openmbee.flexo.mms.sso.oauth.TokenHashing;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Rotating refresh tokens for long-running (e.g. notebook) sessions.
 *
 * - Opaque 48-byte random values; only SHA-256 hashes are stored.
 * - Rotation: presenting a valid token revokes it and issues a successor in the same chain.
 * - Reuse detection: presenting an already-revoked token revokes the entire chain.
 * - Absolute lifetime: successors never extend past the chain's absoluteExpiresAt.
 */
@Service
public class RefreshTokenService {

    private static final Logger log = LoggerFactory.getLogger(RefreshTokenService.class);

    private final RefreshTokenRepository repository;

    /** Rotation window per token (must refresh at least this often), default 1 hour. */
    @Value("${jwt.refresh_duration:3600000}")
    private long refreshDurationMs;

    /** Hard cap on a refresh chain, default 8 hours. */
    @Value("${jwt.refresh_absolute_duration:28800000}")
    private long refreshAbsoluteDurationMs;

    public RefreshTokenService(RefreshTokenRepository repository) {
        this.repository = repository;
    }

    public record IssuedRefreshToken(String value, RefreshToken entity) {}

    /**
     * Start a new refresh chain for a user.
     */
    @Transactional
    public IssuedRefreshToken issue(String userId) {
        return issue(userId, null, null, null, refreshAbsoluteDurationMs);
    }

    /**
     * Start a new refresh chain bound to an OAuth client and resource.
     */
    @Transactional
    public IssuedRefreshToken issue(String userId, String clientId, String resource,
                                    Long rotationWindowMs, long absoluteDurationMs) {
        LocalDateTime absolute = LocalDateTime.now().plusNanos(absoluteDurationMs * 1_000_000);
        RefreshToken template = new RefreshToken();
        template.setUserId(userId);
        template.setChainId(UUID.randomUUID().toString());
        template.setAbsoluteExpiresAt(absolute);
        template.setClientId(clientId);
        template.setResource(resource);
        template.setRotationWindowMs(rotationWindowMs);
        return issueInChain(template);
    }

    /** Finds a presented token without rotating it, e.g. to check client binding first. */
    @Transactional(readOnly = true)
    public Optional<RefreshToken> lookup(String presentedToken) {
        return repository.findByTokenHash(TokenHashing.sha256(presentedToken));
    }

    /**
     * Rotate: validate the presented token, revoke it, and issue a successor in the same chain.
     *
     * @throws UnauthorizedException if the token is unknown, expired, or reused
     */
    @Transactional(noRollbackFor = UnauthorizedException.class)
    public IssuedRefreshToken rotate(String presentedToken) {
        RefreshToken existing = repository.findByTokenHash(TokenHashing.sha256(presentedToken))
                .orElseThrow(() -> new UnauthorizedException("Invalid refresh token"));

        if (existing.isRevoked()) {
            // reuse of a rotated token: assume compromise, revoke the whole chain
            revokeChain(existing.getChainId());
            log.warn("Refresh token reuse detected for user '{}'; chain {} revoked",
                    existing.getUserId(), existing.getChainId());
            throw new UnauthorizedException("Refresh token reuse detected; session revoked");
        }

        if (existing.isExpired()) {
            throw new UnauthorizedException("Refresh token expired");
        }

        existing.setRevoked(true);
        repository.save(existing);

        return issueInChain(existing);
    }

    @Transactional
    public void revokeChain(String chainId) {
        List<RefreshToken> chain = repository.findByChainId(chainId);
        chain.forEach(token -> token.setRevoked(true));
        repository.saveAll(chain);
    }

    @Transactional
    public void purgeExpired() {
        repository.deleteByAbsoluteExpiresAtBefore(LocalDateTime.now());
    }

    private IssuedRefreshToken issueInChain(RefreshToken predecessor) {
        String value = TokenHashing.randomToken(48);
        LocalDateTime absoluteExpiresAt = predecessor.getAbsoluteExpiresAt();
        long window = predecessor.getRotationWindowMs() != null ? predecessor.getRotationWindowMs() : refreshDurationMs;

        LocalDateTime expiresAt = LocalDateTime.now().plusNanos(window * 1_000_000);
        if (expiresAt.isAfter(absoluteExpiresAt)) {
            expiresAt = absoluteExpiresAt;
        }

        RefreshToken entity = new RefreshToken(predecessor.getUserId(), TokenHashing.sha256(value),
                predecessor.getChainId(), expiresAt, absoluteExpiresAt);
        entity.setClientId(predecessor.getClientId());
        entity.setResource(predecessor.getResource());
        entity.setRotationWindowMs(predecessor.getRotationWindowMs());
        repository.save(entity);

        return new IssuedRefreshToken(value, entity);
    }
}
