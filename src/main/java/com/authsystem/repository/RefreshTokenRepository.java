
package com.authsystem.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

import com.authsystem.entity.RefreshToken;

import jakarta.persistence.LockModeType;

public interface RefreshTokenRepository
        extends JpaRepository<RefreshToken, Long> {

    Optional<RefreshToken> findByJti(String jti);

    Optional<RefreshToken> findByJtiAndRevokedFalse(String jti);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
            SELECT rt
            FROM RefreshToken rt
            WHERE rt.jti = :jti
              AND rt.revoked = false
            """)
    Optional<RefreshToken> findActiveTokenForUpdate(
            @Param("jti") String jti);

    @Modifying
    @Transactional
    @Query("""
            UPDATE RefreshToken rt
            SET rt.revoked = true
            WHERE rt.user.id = :userId
              AND rt.revoked = false
            """)
    int revokeAllActiveTokensByUserId(
            @Param("userId") Long userId);
}
