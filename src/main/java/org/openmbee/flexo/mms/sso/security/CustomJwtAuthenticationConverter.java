package org.openmbee.flexo.mms.sso.security;

import org.openmbee.flexo.mms.sso.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Converter that processes JWT tokens and extracts authentication information,
 * including authorities derived from user claims.
 */
@Component
public class CustomJwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private final UserService userService;

    @Autowired
    public CustomJwtAuthenticationConverter(UserService userService) {
        this.userService = userService;
    }

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        // Extract user information and authorities from the JWT token
        Collection<GrantedAuthority> authorities = extractAuthorities(jwt);
        
        String username = extractUsername(jwt);
        
        return new JwtAuthenticationToken(jwt, authorities, username);
    }

    private String extractUsername(Jwt jwt) {
        // Try to extract standard username claims
        if (jwt.hasClaim("preferred_username")) {
            return jwt.getClaimAsString("preferred_username");
        } else if (jwt.hasClaim("email")) {
            return jwt.getClaimAsString("email");
        } else if (jwt.hasClaim("sub")) {
            return jwt.getSubject();
        } else {
            return "unknown";
        }
    }

    private Collection<GrantedAuthority> extractAuthorities(Jwt jwt) {
        Map<String, Object> claims = jwt.getClaims();
        
        // Look for roles or groups in standard claim locations
        if (claims.containsKey("roles")) {
            return getAuthorities(claims, "roles");
        } else if (claims.containsKey("groups")) {
            return getAuthorities(claims, "groups");
        } else if (claims.containsKey("scope")) {
            String scopes = (String) claims.get("scope");
            return extractScopeAuthorities(scopes);
        }
        
        // Default role if no authorities found
        return Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"));
    }

    @SuppressWarnings("unchecked")
    private Collection<GrantedAuthority> getAuthorities(Map<String, Object> claims, String claimName) {
        Object roles = claims.get(claimName);
        if (roles instanceof List) {
            return ((List<String>) roles).stream()
                    .map(role -> new SimpleGrantedAuthority("ROLE_" + role.toUpperCase()))
                    .collect(Collectors.toList());
        }
        return Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"));
    }

    private Collection<GrantedAuthority> extractScopeAuthorities(String scopes) {
        return List.of(scopes.split(" ")).stream()
                .map(scope -> new SimpleGrantedAuthority("SCOPE_" + scope))
                .collect(Collectors.toList());
    }
}