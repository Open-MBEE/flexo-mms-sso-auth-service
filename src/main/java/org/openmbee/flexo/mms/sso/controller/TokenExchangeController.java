package org.openmbee.flexo.mms.sso.controller;

import org.openmbee.flexo.mms.sso.entity.AuthorizationCode;
import org.openmbee.flexo.mms.sso.entity.RefreshToken;
import org.openmbee.flexo.mms.sso.oauth.OAuthClient;
import org.openmbee.flexo.mms.sso.oauth.OAuthClientRegistry;
import org.openmbee.flexo.mms.sso.oauth.OAuthException;
import org.openmbee.flexo.mms.sso.oauth.OAuthServerProperties;
import org.openmbee.flexo.mms.sso.oauth.TokenHashing;
import org.openmbee.flexo.mms.sso.service.AuthorizationCodeService;
import org.openmbee.flexo.mms.sso.service.ProvisioningService;
import org.openmbee.flexo.mms.sso.service.RefreshTokenService;
import org.openmbee.flexo.mms.sso.service.TokenSigner;
import org.openmbee.flexo.mms.sso.service.UserService;
import org.openmbee.flexo.mms.sso.util.UserIdExtractor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * RFC 8693-shaped token endpoint enabling direct IdP-token to layer1-token exchange
 * (e.g. from a JupyterHub pre_spawn_start hook) plus rotating-refresh-token renewal
 * for long-running sessions.
 *
 *   POST /token
 *     grant_type=urn:ietf:params:oauth:grant-type:token-exchange
 *     subject_token=&lt;IdP-issued access or ID token&gt;
 *     subject_token_type=urn:ietf:params:oauth:token-type:access_token
 *
 *   POST /token
 *     grant_type=refresh_token
 *     refresh_token=...
 *
 *   POST /token  (OAuth 2.1 authorization code + PKCE, used by MCP clients)
 *     grant_type=authorization_code
 *     code=...&amp;redirect_uri=...&amp;code_verifier=...&amp;client_id=...
 *
 *   POST /oauth/revoke  (RFC 7009)
 *     token=&lt;refresh token&gt;
 *
 * All grants respond with:
 *   { access_token, issued_token_type, token_type, expires_in, refresh_token }
 */
@RestController
public class TokenExchangeController {

    private static final Logger log = LoggerFactory.getLogger(TokenExchangeController.class);

    private static final String GRANT_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
    private static final String GRANT_REFRESH_TOKEN = "refresh_token";
    private static final String GRANT_AUTHORIZATION_CODE = "authorization_code";
    private static final String TOKEN_TYPE_JWT = "urn:ietf:params:oauth:token-type:jwt";

    private final TokenSigner tokenSigner;
    private final RefreshTokenService refreshTokenService;
    private final ProvisioningService provisioningService;
    private final UserService userService;
    private final UserIdExtractor userIdExtractor;
    private final OAuthServerProperties oauthProperties;
    private final OAuthClientRegistry clientRegistry;
    private final AuthorizationCodeService codeService;

    /** Issuer whose tokens are accepted as subject_token; defaults to the configured OIDC login provider. */
    @Value("${flexo.sso-auth-service.idp_issuer_uri:${spring.security.oauth2.client.provider.oidc.issuer-uri:}}")
    private String idpIssuerUri;

    /** Optional audience the subject_token must carry; empty disables the check. */
    @Value("${flexo.sso-auth-service.idp_audience:}")
    private String idpAudience;

    @Value("${flexo.sso-auth-service.group_claims_field:groups}")
    private String groupClaimsField;

    /** Access-token TTL for /token issuance; deliberately shorter than the legacy /login jwt.duration. */
    @Value("${jwt.access_duration:3600000}")
    private long accessDurationMs;

    private volatile JwtDecoder idpDecoder;

    public TokenExchangeController(TokenSigner tokenSigner,
                                   RefreshTokenService refreshTokenService,
                                   ProvisioningService provisioningService,
                                   UserService userService,
                                   UserIdExtractor userIdExtractor,
                                   OAuthServerProperties oauthProperties,
                                   OAuthClientRegistry clientRegistry,
                                   AuthorizationCodeService codeService) {
        this.oauthProperties = oauthProperties;
        this.clientRegistry = clientRegistry;
        this.codeService = codeService;
        this.tokenSigner = tokenSigner;
        this.refreshTokenService = refreshTokenService;
        this.provisioningService = provisioningService;
        this.userService = userService;
        this.userIdExtractor = userIdExtractor;
    }

    @PostMapping(value = "/token", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<Map<String, Object>> token(@RequestParam Map<String, String> form,
                                                     @RequestHeader(value = "Authorization", required = false) String authorization) {
        String grantType = form.get("grant_type");

        try {
            if (GRANT_TOKEN_EXCHANGE.equals(grantType)) {
                return exchange(form);
            } else if (GRANT_REFRESH_TOKEN.equals(grantType)) {
                return refresh(form, authorization);
            } else if (GRANT_AUTHORIZATION_CODE.equals(grantType) && oauthProperties.isEnabled()) {
                return authorizationCode(form, authorization);
            }
        } catch (OAuthException e) {
            return oauthError(e, authorization);
        }

        return oauthError(HttpStatus.BAD_REQUEST, "unsupported_grant_type",
                "grant_type must be '" + GRANT_TOKEN_EXCHANGE + "', '" + GRANT_REFRESH_TOKEN
                        + "' or '" + GRANT_AUTHORIZATION_CODE + "'");
    }

    @PostMapping(value = "/oauth/revoke", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<Map<String, Object>> revoke(@RequestParam Map<String, String> form,
                                                      @RequestHeader(value = "Authorization", required = false) String authorization) {
        if (!oauthProperties.isEnabled()) {
            return ResponseEntity.notFound().build();
        }
        try {
            OAuthClient client = clientRegistry.authenticate(authorization, form);
            String token = form.get("token");
            if (token == null || token.isBlank()) {
                throw OAuthException.invalidRequest("token is required");
            }
            // only refresh tokens are revocable; unknown tokens still return 200 (RFC 7009 section 2.2)
            refreshTokenService.lookup(token)
                    .filter(rt -> client.clientId().equals(rt.getClientId()))
                    .ifPresent(rt -> refreshTokenService.revokeChain(rt.getChainId()));
            return ResponseEntity.ok().headers(noStore()).build();
        } catch (OAuthException e) {
            return oauthError(e, authorization);
        }
    }

    private ResponseEntity<Map<String, Object>> authorizationCode(Map<String, String> form, String authorization) {
        OAuthClient client = clientRegistry.authenticate(authorization, form);
        String resource = form.get("resource");
        AuthorizationCode code = codeService.redeem(form.get("code"), c -> {
            if (!c.getClientId().equals(client.clientId())) {
                throw OAuthException.invalidGrant("authorization code was issued to another client");
            }
            if (!c.getRedirectUri().equals(form.get("redirect_uri"))) {
                throw OAuthException.invalidGrant("redirect_uri does not match the authorization request");
            }
            if (!TokenHashing.verifyPkce(form.get("code_verifier"), c.getCodeChallenge())) {
                throw OAuthException.invalidGrant("PKCE verification failed");
            }
            if (resource != null && !OAuthServerProperties.stripTrailingSlash(resource)
                    .equals(OAuthServerProperties.stripTrailingSlash(c.getResource()))) {
                throw new OAuthException(HttpStatus.BAD_REQUEST, "invalid_target", "resource does not match the authorization request");
            }
        });

        String userId = code.getUserId();
        List<String> groups = userService.getStoredGroups(userId);
        RefreshTokenService.IssuedRefreshToken refreshToken = refreshTokenService.issue(userId, client.clientId(),
                code.getResource(), oauthProperties.getRefreshDuration(), oauthProperties.getRefreshAbsoluteDuration());
        codeService.recordChain(code, refreshToken.entity().getChainId());

        log.info("issued OAuth tokens to client '{}' for user '{}'", client.clientId(), userId);
        return issue(userId, groups, refreshToken, code.getScope());
    }

    private ResponseEntity<Map<String, Object>> exchange(Map<String, String> form) {
        String subjectToken = form.get("subject_token");
        if (subjectToken == null || subjectToken.isBlank()) {
            return oauthError(HttpStatus.BAD_REQUEST, "invalid_request", "subject_token is required");
        }

        Jwt jwt;
        try {
            jwt = idpDecoder().decode(subjectToken);
        } catch (IllegalStateException e) {
            return oauthError(HttpStatus.BAD_REQUEST, "invalid_request", e.getMessage());
        } catch (JwtException e) {
            log.debug("subject_token rejected: {}", e.getMessage());
            return oauthError(HttpStatus.UNAUTHORIZED, "invalid_grant", "subject_token validation failed");
        }

        if (!idpAudience.isBlank()
                && (jwt.getAudience() == null || !jwt.getAudience().contains(idpAudience))) {
            return oauthError(HttpStatus.UNAUTHORIZED, "invalid_grant", "subject_token audience mismatch");
        }

        String userId = userIdExtractor.extractUserIdFromJwt(jwt);
        if (userId == null || userId.isBlank() || "unknown".equals(userId) || "anonymous".equals(userId)) {
            return oauthError(HttpStatus.UNAUTHORIZED, "invalid_grant", "could not determine user id from subject_token");
        }

        List<String> groups = extractGroups(jwt);

        // keep the local user record fresh (groups are re-read from here on refresh)
        userService.saveOrUpdateUser(userId, jwt.getClaimAsString("name"), jwt.getClaimAsString("email"), groups);

        return issue(userId, groups);
    }

    private ResponseEntity<Map<String, Object>> refresh(Map<String, String> form, String authorization) {
        String refreshToken = form.get("refresh_token");
        if (refreshToken == null || refreshToken.isBlank()) {
            return oauthError(HttpStatus.BAD_REQUEST, "invalid_request", "refresh_token is required");
        }

        // chains issued to an OAuth client may only be refreshed by that client
        Optional<RefreshToken> presented = refreshTokenService.lookup(refreshToken);
        String boundClient = presented.map(RefreshToken::getClientId).orElse(null);
        if (boundClient != null) {
            OAuthClient client = clientRegistry.authenticate(authorization, form);
            if (!boundClient.equals(client.clientId())) {
                throw OAuthException.invalidGrant("refresh token was issued to another client");
            }
        }

        RefreshTokenService.IssuedRefreshToken rotated;
        try {
            rotated = refreshTokenService.rotate(refreshToken);
        } catch (org.openmbee.flexo.mms.sso.exception.UnauthorizedException e) {
            return oauthError(HttpStatus.UNAUTHORIZED, "invalid_grant", e.getMessage());
        }

        String userId = rotated.entity().getUserId();

        // re-read groups from the user record so IdP membership changes propagate at refresh time
        List<String> groups = boundClient != null ? userService.getStoredGroups(userId) : userService.getUserGroups(userId);

        return issue(userId, groups, rotated, null);
    }

    private ResponseEntity<Map<String, Object>> issue(String userId, List<String> groups) {
        return issue(userId, groups, refreshTokenService.issue(userId), null);
    }

    private ResponseEntity<Map<String, Object>> issue(String userId, List<String> groups,
                                                      RefreshTokenService.IssuedRefreshToken refreshToken, String scope) {
        // ensure orgs/groups/policies exist in layer1 for any org-encoding groups (no-op if disabled)
        provisioningService.provisionForGroups(groups);

        RefreshToken chain = refreshToken.entity();
        boolean oauthChain = chain.getClientId() != null;
        long durationMs = oauthChain ? oauthProperties.getAccessDuration() : accessDurationMs;
        String accessToken = oauthChain
                ? tokenSigner.sign(userId, groups, durationMs,
                        chain.getResource() != null ? List.of(chain.getResource()) : List.of(), chain.getClientId())
                : tokenSigner.sign(userId, groups, durationMs);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("access_token", accessToken);
        body.put("issued_token_type", TOKEN_TYPE_JWT);
        body.put("token_type", "Bearer");
        body.put("expires_in", durationMs / 1000);
        body.put("refresh_token", refreshToken.value());
        if (scope != null) {
            body.put("scope", scope);
        }

        return ResponseEntity.ok().headers(noStore()).body(body);
    }

    private static org.springframework.http.HttpHeaders noStore() {
        org.springframework.http.HttpHeaders headers = new org.springframework.http.HttpHeaders();
        headers.setCacheControl("no-store");
        headers.setPragma("no-cache");
        return headers;
    }

    private List<String> extractGroups(Jwt jwt) {
        if (jwt.hasClaim(groupClaimsField)) {
            List<String> groups = jwt.getClaimAsStringList(groupClaimsField);
            if (groups != null) {
                return new ArrayList<>(groups);
            }
        }
        return new ArrayList<>();
    }

    private JwtDecoder idpDecoder() {
        JwtDecoder decoder = idpDecoder;
        if (decoder == null) {
            synchronized (this) {
                if (idpDecoder == null) {
                    if (idpIssuerUri == null || idpIssuerUri.isBlank()) {
                        throw new IllegalStateException(
                                "no IdP issuer configured (flexo.sso-auth-service.idp_issuer_uri)");
                    }
                    idpDecoder = JwtDecoders.fromIssuerLocation(idpIssuerUri);
                }
                decoder = idpDecoder;
            }
        }
        return decoder;
    }

    private static ResponseEntity<Map<String, Object>> oauthError(OAuthException e, String authorization) {
        ResponseEntity<Map<String, Object>> response = oauthError(e.getStatus(), e.getError(), e.getMessage());
        if (e.getStatus() == HttpStatus.UNAUTHORIZED && authorization != null
                && authorization.regionMatches(true, 0, "Basic ", 0, 6)) {
            return ResponseEntity.status(e.getStatus())
                    .header("WWW-Authenticate", "Basic realm=\"oauth\"")
                    .body(response.getBody());
        }
        return response;
    }

    private static ResponseEntity<Map<String, Object>> oauthError(HttpStatus status, String error, String description) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", error);
        body.put("error_description", description);
        return ResponseEntity.status(status).headers(noStore()).body(body);
    }
}
