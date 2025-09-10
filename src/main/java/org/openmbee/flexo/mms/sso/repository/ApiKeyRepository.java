package org.openmbee.flexo.mms.sso.repository;

import org.openmbee.flexo.mms.sso.entity.ApiKey;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface ApiKeyRepository extends JpaRepository<ApiKey, Long> {
    
    List<ApiKey> findByUserId(String userId);
    
    Optional<ApiKey> findByKeyValue(String keyValue);
    
    void deleteByUserIdAndId(String userId, Long id);
}