package org.openmbee.flexo.mms.sso.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.openmbee.flexo.mms.sso.entity.User;
import org.openmbee.flexo.mms.sso.oauth.OAuthClient;
import org.openmbee.flexo.mms.sso.oauth.OAuthClientRegistry;
import org.openmbee.flexo.mms.sso.oauth.OAuthException;
import org.openmbee.flexo.mms.sso.oauth.OAuthServerProperties;
import org.openmbee.flexo.mms.sso.oauth.TokenHashing;
import org.openmbee.flexo.mms.sso.service.AuthorizationCodeService;
import org.openmbee.flexo.mms.sso.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.ModelAndView;

import java.io.Serializable;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * OAuth 2.1 authorization endpoint (authorization code + PKCE S256) for MCP clients.
 * The user is authenticated through the configured upstream SSO login before reaching this endpoint.
 */
@Controller
public class OAuthAuthorizationController {

    static final String PENDING_SESSION_KEY = "flexo.oauth.pending";
    private static final long PENDING_TTL_MS = 10L * 60 * 1000;

    private final OAuthServerProperties properties;
    private final OAuthClientRegistry clientRegistry;
    private final AuthorizationCodeService codeService;
    private final UserService userService;

    public OAuthAuthorizationController(OAuthServerProperties properties, OAuthClientRegistry clientRegistry,
                                        AuthorizationCodeService codeService, UserService userService) {
        this.properties = properties;
        this.clientRegistry = clientRegistry;
        this.codeService = codeService;
        this.userService = userService;
    }

    record PendingAuthorization(String clientId, String redirectUri, String codeChallenge, String resource,
                                String scope, String state, String userId, long createdAt) implements Serializable {}

    @GetMapping("/oauth/authorize")
    public ModelAndView authorize(@RequestParam MultiValueMap<String, String> params, Authentication authentication,
                                  HttpServletRequest request, HttpServletResponse response) {
        requireEnabled();

        String clientId = single(params, "client_id");
        String redirectUri = single(params, "redirect_uri");
        String state = params.getFirst("state");

        OAuthClient client;
        try {
            client = clientRegistry.find(clientId).orElse(null);
        } catch (OAuthException e) {
            return errorPage(e.getMessage());
        }
        if (client == null) {
            return errorPage("Unknown client_id.");
        }
        if (!client.allowsRedirectUri(redirectUri)) {
            return errorPage("The redirect_uri is not registered for this client.");
        }

        // from here on, errors are reported to the client's redirect_uri
        String issuer = properties.resolveIssuer(request);
        try {
            if (!"code".equals(single(params, "response_type"))) {
                throw new OAuthException(HttpStatus.BAD_REQUEST, "unsupported_response_type", "response_type must be 'code'");
            }
            String challenge = single(params, "code_challenge");
            if (!"S256".equals(single(params, "code_challenge_method")) || !TokenHashing.isValidCodeChallenge(challenge)) {
                throw OAuthException.invalidRequest("PKCE with code_challenge_method=S256 is required");
            }
            String resource = resolveResource(params.get("resource"));
            String scope = validateScope(params.getFirst("scope"));

            User user = currentUser(authentication);
            PendingAuthorization pending = new PendingAuthorization(client.clientId(), redirectUri, challenge,
                    resource, scope, state, user.getUserId(), System.currentTimeMillis());

            if (client.trusted() && !properties.isAlwaysConsent()) {
                return redirectWithCode(pending, issuer, response);
            }
            return consentPage(client, pending, user, request.getSession());
        } catch (OAuthException e) {
            return redirect(withParams(redirectUri, errorParams(e, state, issuer)), response);
        }
    }

    @PostMapping("/oauth/authorize/consent")
    public ModelAndView consent(@RequestParam("request_id") String requestId,
                                @RequestParam(value = "decision", defaultValue = "deny") String decision,
                                Authentication authentication, HttpServletRequest request,
                                HttpServletResponse response) {
        requireEnabled();

        PendingAuthorization pending = pendingRequests(request.getSession()).remove(requestId);
        if (pending == null || System.currentTimeMillis() - pending.createdAt() > PENDING_TTL_MS) {
            return errorPage("This authorization request has expired. Please start again from your MCP client.");
        }
        User user = currentUser(authentication);
        if (!user.getUserId().equals(pending.userId())) {
            return errorPage("This authorization request belongs to a different user.");
        }

        String issuer = properties.resolveIssuer(request);
        if (!"approve".equals(decision)) {
            OAuthException denied = new OAuthException(HttpStatus.FORBIDDEN, "access_denied", "the user denied the request");
            return redirect(withParams(pending.redirectUri(), errorParams(denied, pending.state(), issuer)), response);
        }
        return redirectWithCode(pending, issuer, response);
    }

    private ModelAndView redirectWithCode(PendingAuthorization pending, String issuer, HttpServletResponse response) {
        String code = codeService.create(pending.clientId(), pending.redirectUri(), pending.codeChallenge(),
                pending.resource(), pending.scope(), pending.userId());
        Map<String, String> params = new LinkedHashMap<>();
        params.put("code", code);
        if (pending.state() != null) {
            params.put("state", pending.state());
        }
        params.put("iss", issuer);
        return redirect(withParams(pending.redirectUri(), params), response);
    }

    private ModelAndView consentPage(OAuthClient client, PendingAuthorization pending, User user, HttpSession session) {
        Map<String, PendingAuthorization> requests = pendingRequests(session);
        requests.values().removeIf(p -> System.currentTimeMillis() - p.createdAt() > PENDING_TTL_MS);
        String requestId = TokenHashing.randomToken(24);
        requests.put(requestId, pending);
        session.setAttribute(PENDING_SESSION_KEY, requests);

        ModelAndView mav = new ModelAndView("oauth-consent");
        mav.addObject("requestId", requestId);
        mav.addObject("clientName", client.displayName());
        mav.addObject("clientId", client.clientId());
        mav.addObject("metadataDocument", client.metadataDocument());
        mav.addObject("redirectHost", redirectHost(pending.redirectUri()));
        mav.addObject("resource", pending.resource());
        mav.addObject("scope", pending.scope());
        mav.addObject("userName", user.getName() != null ? user.getName() : user.getUserId());
        return mav;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, PendingAuthorization> pendingRequests(HttpSession session) {
        Object existing = session.getAttribute(PENDING_SESSION_KEY);
        if (existing instanceof Map<?, ?> map) {
            return (Map<String, PendingAuthorization>) map;
        }
        Map<String, PendingAuthorization> created = new LinkedHashMap<>();
        session.setAttribute(PENDING_SESSION_KEY, created);
        return created;
    }

    private String resolveResource(List<String> requested) {
        List<String> allowed = properties.getResources().stream().map(OAuthServerProperties::stripTrailingSlash).toList();
        if (requested == null || requested.isEmpty()) {
            if (allowed.size() == 1) {
                return allowed.get(0);
            }
            throw new OAuthException(HttpStatus.BAD_REQUEST, "invalid_target", "resource parameter is required");
        }
        if (requested.size() > 1) {
            throw new OAuthException(HttpStatus.BAD_REQUEST, "invalid_target", "exactly one resource may be requested");
        }
        String resource = OAuthServerProperties.stripTrailingSlash(requested.get(0));
        if (!allowed.contains(resource)) {
            throw new OAuthException(HttpStatus.BAD_REQUEST, "invalid_target", "resource is not served by this authorization server");
        }
        return resource;
    }

    private String validateScope(String scope) {
        if (scope == null || scope.isBlank()) {
            return null;
        }
        List<String> allowed = properties.getScopes();
        if (!allowed.isEmpty()) {
            for (String s : scope.trim().split("\\s+")) {
                if (!allowed.contains(s)) {
                    throw new OAuthException(HttpStatus.BAD_REQUEST, "invalid_scope", "unsupported scope: " + s);
                }
            }
        }
        return String.join(" ", Arrays.asList(scope.trim().split("\\s+")));
    }

    private User currentUser(Authentication authentication) {
        if (authentication == null || !(authentication.getPrincipal() instanceof OidcUser oidcUser)) {
            throw new OAuthException(HttpStatus.FORBIDDEN, "access_denied", "SSO login is required");
        }
        return userService.syncOidcUser(oidcUser);
    }

    private void requireEnabled() {
        if (!properties.isEnabled()) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }
    }

    private static String single(MultiValueMap<String, String> params, String name) {
        List<String> values = params.get(name);
        if (values == null || values.isEmpty() || values.get(0) == null || values.get(0).isBlank()) {
            throw OAuthException.invalidRequest(name + " is required");
        }
        if (values.size() > 1) {
            throw OAuthException.invalidRequest(name + " must not be repeated");
        }
        return values.get(0);
    }

    private static Map<String, String> errorParams(OAuthException e, String state, String issuer) {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("error", e.getError());
        params.put("error_description", e.getMessage());
        if (state != null) {
            params.put("state", state);
        }
        params.put("iss", issuer);
        return params;
    }

    static String withParams(String uri, Map<String, String> params) {
        StringBuilder sb = new StringBuilder(uri);
        char sep = uri.contains("?") ? '&' : '?';
        for (Map.Entry<String, String> e : params.entrySet()) {
            sb.append(sep).append(URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8))
                    .append('=').append(URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8));
            sep = '&';
        }
        return sb.toString();
    }

    private static String redirectHost(String redirectUri) {
        try {
            URI uri = URI.create(redirectUri);
            return uri.getHost() != null ? uri.getScheme() + "://" + uri.getAuthority() : uri.getScheme() + ":";
        } catch (IllegalArgumentException e) {
            return redirectUri;
        }
    }

    private static ModelAndView redirect(String location, HttpServletResponse response) {
        response.setStatus(HttpServletResponse.SC_FOUND);
        response.setHeader("Location", location);
        response.setHeader("Cache-Control", "no-store");
        return null;
    }

    private static ModelAndView errorPage(String message) {
        // never redirect to an unverified redirect_uri (RFC 6749 section 4.1.2.1)
        ModelAndView mav = new ModelAndView("oauth-error");
        mav.addObject("message", message);
        mav.setStatus(HttpStatus.BAD_REQUEST);
        return mav;
    }
}
