package org.openmbee.flexo.mms.sso.repository;

import org.openmbee.flexo.mms.sso.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    Optional<RefreshToken> findByTokenHash(String tokenHash);

    List<RefreshToken> findByChainId(String chainId);

    void deleteByAbsoluteExpiresAtBefore(LocalDateTime cutoff);
}
