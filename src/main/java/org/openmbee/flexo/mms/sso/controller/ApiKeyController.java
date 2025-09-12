package org.openmbee.flexo.mms.sso.controller;

import org.openmbee.flexo.mms.sso.entity.ApiKey;
import org.openmbee.flexo.mms.sso.service.ApiKeyService;
import org.openmbee.flexo.mms.sso.util.UserIdExtractor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Controller
@RequestMapping("/keys")
public class ApiKeyController {

    private final ApiKeyService apiKeyService;
    private final UserIdExtractor userIdExtractor;

    @Autowired
    public ApiKeyController(ApiKeyService apiKeyService, UserIdExtractor userIdExtractor) {
        this.apiKeyService = apiKeyService;
        this.userIdExtractor = userIdExtractor;
    }

    @GetMapping
    public String listKeys(Authentication authentication, Model model) {
        String userId = userIdExtractor.extractUserId(authentication);
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

        String userId = userIdExtractor.extractUserId(authentication);
        ApiKey newKey = apiKeyService.generateApiKey(userId, name, description, validityDays);

        List<ApiKey> apiKeys = apiKeyService.getApiKeysForUser(userId);
        model.addAttribute("apiKeys", apiKeys);
        model.addAttribute("newKey", newKey);

        return "api-keys";
    }

    @PostMapping("/revoke/{keyId}")
    public String revokeKey(Authentication authentication, @PathVariable Long keyId) {
        String userId = userIdExtractor.extractUserId(authentication);
        apiKeyService.revokeApiKey(userId, keyId);
        return "redirect:/keys";
    }

}