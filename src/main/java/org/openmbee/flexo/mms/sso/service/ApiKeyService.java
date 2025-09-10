package org.openmbee.flexo.mms.sso.service;

import org.openmbee.flexo.mms.sso.entity.ApiKey;
import org.openmbee.flexo.mms.sso.repository.ApiKeyRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

@Service
public class ApiKeyService {

    private final ApiKeyRepository apiKeyRepository;
    private static final SecureRandom secureRandom = new SecureRandom();

    @Autowired
    public ApiKeyService(ApiKeyRepository apiKeyRepository) {
        this.apiKeyRepository = apiKeyRepository;
    }

    public List<ApiKey> getApiKeysForUser(String userId) {
        return apiKeyRepository.findByUserId(userId);
    }

    @Transactional
    public ApiKey generateApiKey(String userId, String name, String description, Integer validityDays) {
        byte[] randomBytes = new byte[32];
        secureRandom.nextBytes(randomBytes);
        String keyValue = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);

        LocalDateTime expiresAt = validityDays != null ?
                LocalDateTime.now().plusDays(validityDays) : null;

        ApiKey apiKey = new ApiKey(userId, keyValue, name, description, expiresAt);
        return apiKeyRepository.save(apiKey);
    }

    @Transactional
    public void revokeApiKey(String userId, Long keyId) {
        apiKeyRepository.deleteByUserIdAndId(userId, keyId);
    }

    @Transactional
    public Optional<ApiKey> validateApiKey(String keyValue) {
        Optional<ApiKey> apiKeyOpt = apiKeyRepository.findByKeyValue(keyValue);

        if (apiKeyOpt.isPresent()) {
            ApiKey apiKey = apiKeyOpt.get();

            // Check if the key is expired
            if (apiKey.isExpired()) {
                return Optional.empty();
            }

            // Update last used timestamp
            apiKey.setLastUsedAt(LocalDateTime.now());
            apiKeyRepository.save(apiKey);
            return Optional.of(apiKey);
        }

        return Optional.empty();
    }
}