package org.openmbee.flexo.mms.sso.repository;

import org.openmbee.flexo.mms.sso.entity.AuthorizationCode;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;

@Repository
public interface AuthorizationCodeRepository extends JpaRepository<AuthorizationCode, Long> {

    Optional<AuthorizationCode> findByCodeHash(String codeHash);

    /** Atomically claims an unused code; returns 0 if it was already redeemed. */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("update AuthorizationCode c set c.used = true where c.id = :id and c.used = false")
    int markUsed(@Param("id") Long id);

    void deleteByExpiresAtBefore(LocalDateTime cutoff);
}
