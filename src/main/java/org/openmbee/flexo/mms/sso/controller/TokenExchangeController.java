package org.openmbee.flexo.mms.sso.controller;

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
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

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
 * Both grants respond with:
 *   { access_token, issued_token_type, token_type, expires_in, refresh_token }
 */
@RestController
public class TokenExchangeController {

    private static final Logger log = LoggerFactory.getLogger(TokenExchangeController.class);

    private static final String GRANT_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
    private static final String GRANT_REFRESH_TOKEN = "refresh_token";
    private static final String TOKEN_TYPE_JWT = "urn:ietf:params:oauth:token-type:jwt";

    private final TokenSigner tokenSigner;
    private final RefreshTokenService refreshTokenService;
    private final ProvisioningService provisioningService;
    private final UserService userService;
    private final UserIdExtractor userIdExtractor;

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
                                   UserIdExtractor userIdExtractor) {
        this.tokenSigner = tokenSigner;
        this.refreshTokenService = refreshTokenService;
        this.provisioningService = provisioningService;
        this.userService = userService;
        this.userIdExtractor = userIdExtractor;
    }

    @PostMapping(value = "/token", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<Map<String, Object>> token(@RequestParam Map<String, String> form) {
        String grantType = form.get("grant_type");

        if (GRANT_TOKEN_EXCHANGE.equals(grantType)) {
            return exchange(form);
        } else if (GRANT_REFRESH_TOKEN.equals(grantType)) {
            return refresh(form);
        }

        return oauthError(HttpStatus.BAD_REQUEST, "unsupported_grant_type",
                "grant_type must be '" + GRANT_TOKEN_EXCHANGE + "' or '" + GRANT_REFRESH_TOKEN + "'");
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

    private ResponseEntity<Map<String, Object>> refresh(Map<String, String> form) {
        String refreshToken = form.get("refresh_token");
        if (refreshToken == null || refreshToken.isBlank()) {
            return oauthError(HttpStatus.BAD_REQUEST, "invalid_request", "refresh_token is required");
        }

        RefreshTokenService.IssuedRefreshToken rotated;
        try {
            rotated = refreshTokenService.rotate(refreshToken);
        } catch (org.openmbee.flexo.mms.sso.exception.UnauthorizedException e) {
            return oauthError(HttpStatus.UNAUTHORIZED, "invalid_grant", e.getMessage());
        }

        String userId = rotated.entity().getUserId();

        // re-read groups from the user record so IdP membership changes propagate at refresh time
        List<String> groups = userService.getUserGroups(userId);

        return issue(userId, groups, rotated);
    }

    private ResponseEntity<Map<String, Object>> issue(String userId, List<String> groups) {
        return issue(userId, groups, refreshTokenService.issue(userId));
    }

    private ResponseEntity<Map<String, Object>> issue(String userId, List<String> groups,
                                                      RefreshTokenService.IssuedRefreshToken refreshToken) {
        // ensure orgs/groups/policies exist in layer1 for any org-encoding groups (no-op if disabled)
        provisioningService.provisionForGroups(groups);

        String accessToken = tokenSigner.sign(userId, groups, accessDurationMs);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("access_token", accessToken);
        body.put("issued_token_type", TOKEN_TYPE_JWT);
        body.put("token_type", "Bearer");
        body.put("expires_in", accessDurationMs / 1000);
        body.put("refresh_token", refreshToken.value());

        return ResponseEntity.ok(body);
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

    private static ResponseEntity<Map<String, Object>> oauthError(HttpStatus status, String error, String description) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", error);
        body.put("error_description", description);
        return ResponseEntity.status(status).body(body);
    }
}
