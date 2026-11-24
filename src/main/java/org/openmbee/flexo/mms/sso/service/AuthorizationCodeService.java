package org.openmbee.flexo.mms.sso.service;

import org.openmbee.flexo.mms.sso.entity.AuthorizationCode;
import org.openmbee.flexo.mms.sso.oauth.OAuthException;
import org.openmbee.flexo.mms.sso.oauth.OAuthServerProperties;
import org.openmbee.flexo.mms.sso.oauth.TokenHashing;
import org.openmbee.flexo.mms.sso.repository.AuthorizationCodeRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.function.Consumer;

@Service
public class AuthorizationCodeService {

    private static final Logger log = LoggerFactory.getLogger(AuthorizationCodeService.class);

    private final AuthorizationCodeRepository repository;
    private final RefreshTokenService refreshTokenService;
    private final OAuthServerProperties properties;

    public AuthorizationCodeService(AuthorizationCodeRepository repository,
                                    RefreshTokenService refreshTokenService,
                                    OAuthServerProperties properties) {
        this.repository = repository;
        this.refreshTokenService = refreshTokenService;
        this.properties = properties;
    }

    @Transactional
    public String create(String clientId, String redirectUri, String codeChallenge,
                         String resource, String scope, String userId) {
        repository.deleteByExpiresAtBefore(LocalDateTime.now().minusMinutes(5));
        String code = TokenHashing.randomToken(32);
        LocalDateTime expiresAt = LocalDateTime.now().plusNanos(properties.getCodeDuration() * 1_000_000);
        repository.save(new AuthorizationCode(TokenHashing.sha256(code), clientId, redirectUri,
                codeChallenge, resource, scope, userId, expiresAt));
        return code;
    }

    /**
     * Redeems a code exactly once, after {@code checks} (client, redirect, PKCE) pass.
     * A replayed code revokes the refresh chain issued from it (RFC 6749 section 4.1.2).
     */
    @Transactional(noRollbackFor = OAuthException.class)
    public AuthorizationCode redeem(String code, Consumer<AuthorizationCode> checks) {
        if (code == null || code.isBlank()) {
            throw OAuthException.invalidRequest("code is required");
        }
        AuthorizationCode stored = repository.findByCodeHash(TokenHashing.sha256(code))
                .orElseThrow(() -> OAuthException.invalidGrant("invalid authorization code"));
        checks.accept(stored);

        if (repository.markUsed(stored.getId()) == 0) {
            if (stored.getChainId() != null) {
                refreshTokenService.revokeChain(stored.getChainId());
            }
            log.warn("authorization code replay for client '{}', user '{}'", stored.getClientId(), stored.getUserId());
            throw OAuthException.invalidGrant("authorization code already used");
        }
        if (stored.isExpired()) {
            throw OAuthException.invalidGrant("authorization code expired");
        }
        return stored;
    }

    @Transactional
    public void recordChain(AuthorizationCode code, String chainId) {
        repository.findById(code.getId()).ifPresent(c -> {
            c.setChainId(chainId);
            repository.save(c);
        });
    }
}
