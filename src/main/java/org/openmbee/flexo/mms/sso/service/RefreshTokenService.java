package org.openmbee.flexo.mms.sso.service;

import org.openmbee.flexo.mms.sso.entity.RefreshToken;
import org.openmbee.flexo.mms.sso.exception.UnauthorizedException;
import org.openmbee.flexo.mms.sso.repository.RefreshTokenRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.List;
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
    private final SecureRandom secureRandom = new SecureRandom();

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
        LocalDateTime now = LocalDateTime.now();
        LocalDateTime absolute = now.plusNanos(refreshAbsoluteDurationMs * 1_000_000);
        return issueInChain(userId, UUID.randomUUID().toString(), absolute);
    }

    /**
     * Rotate: validate the presented token, revoke it, and issue a successor in the same chain.
     *
     * @throws UnauthorizedException if the token is unknown, expired, or reused
     */
    @Transactional
    public IssuedRefreshToken rotate(String presentedToken) {
        RefreshToken existing = repository.findByTokenHash(hash(presentedToken))
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

        return issueInChain(existing.getUserId(), existing.getChainId(), existing.getAbsoluteExpiresAt());
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

    private IssuedRefreshToken issueInChain(String userId, String chainId, LocalDateTime absoluteExpiresAt) {
        byte[] raw = new byte[48];
        secureRandom.nextBytes(raw);
        String value = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);

        LocalDateTime expiresAt = LocalDateTime.now().plusNanos(refreshDurationMs * 1_000_000);
        if (expiresAt.isAfter(absoluteExpiresAt)) {
            expiresAt = absoluteExpiresAt;
        }

        RefreshToken entity = new RefreshToken(userId, hash(value), chainId, expiresAt, absoluteExpiresAt);
        repository.save(entity);

        return new IssuedRefreshToken(value, entity);
    }

    private static String hash(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashed = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hashed);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
