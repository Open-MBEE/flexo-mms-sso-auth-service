package org.openmbee.flexo.mms.sso.controller;

import org.openmbee.flexo.mms.sso.entity.ApiKey;
import org.openmbee.flexo.mms.sso.service.ApiKeyService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Controller
@RequestMapping("/keys")
public class ApiKeyController {

    private final ApiKeyService apiKeyService;

    @Autowired
    public ApiKeyController(ApiKeyService apiKeyService) {
        this.apiKeyService = apiKeyService;
    }

    @GetMapping
    public String listKeys(Authentication authentication, Model model) {
        String userId = getUserId(authentication);
        List<ApiKey> apiKeys = apiKeyService.getApiKeysForUser(userId);
        model.addAttribute("apiKeys", apiKeys);
        model.addAttribute("newKey", null); // For newly generated key display
        return "api-keys";
    }

    @PostMapping("/generate")
    public String generateKey(
            Authentication authentication,
            @RequestParam("name") String name,
            @RequestParam("description") String description,
            @RequestParam(value = "validityDays", required = false) Integer validityDays,
            Model model) {

        String userId = getUserId(authentication);
        ApiKey newKey = apiKeyService.generateApiKey(userId, name, description, validityDays);

        List<ApiKey> apiKeys = apiKeyService.getApiKeysForUser(userId);
        model.addAttribute("apiKeys", apiKeys);
        model.addAttribute("newKey", newKey);

        return "api-keys";
    }

    @PostMapping("/revoke/{keyId}")
    public String revokeKey(Authentication authentication, @PathVariable Long keyId) {
        String userId = getUserId(authentication);
        apiKeyService.revokeApiKey(userId, keyId);
        return "redirect:/keys";
    }

    private String getUserId(Authentication authentication) {
        if (authentication.getPrincipal() instanceof OidcUser) {
            OidcUser oidcUser = (OidcUser) authentication.getPrincipal();
            return oidcUser.getSubject();
        }
        return authentication.getName();
    }
}