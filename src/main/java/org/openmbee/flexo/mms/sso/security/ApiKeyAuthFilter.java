package org.openmbee.flexo.mms.sso.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.openmbee.flexo.mms.sso.entity.ApiKey;
import org.openmbee.flexo.mms.sso.service.ApiKeyService;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;
import java.util.Optional;

public class ApiKeyAuthFilter extends OncePerRequestFilter {

    private final ApiKeyService apiKeyService;

    public ApiKeyAuthFilter(ApiKeyService apiKeyService) {
        this.apiKeyService = apiKeyService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // Try to get the API key from the Authorization Bearer header
        String authHeader = request.getHeader("Authorization");
        String apiKey = null;
        
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            apiKey = authHeader.substring(7);
        }
        
        // For backward compatibility: check X-API-KEY header
        if (apiKey == null) {
            apiKey = request.getHeader("X-API-KEY");
        }

        // If header not present, check query parameter "apiKey" as a fallback
        if (apiKey == null) {
            apiKey = request.getParameter("apiKey");
        }

        // If we have an API key, validate it
        if (apiKey != null) {
            Optional<ApiKey> validatedKey = apiKeyService.validateApiKey(apiKey);

            if (validatedKey.isPresent()) {
                ApiKey key = validatedKey.get();

                // Create authentication token with the user ID from the API key
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        key.getUserId(),
                        null,
                        Collections.singletonList(new SimpleGrantedAuthority("ROLE_API_USER"))
                );

                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }

        filterChain.doFilter(request, response);
    }
}