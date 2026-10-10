package com.authsystem.repository;

import com.authsystem.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RefreshTokenRepository
        extends JpaRepository<RefreshToken, Long> {

    Optional<RefreshToken> findByJti(String jti);

    Optional<RefreshToken> findByJtiAndRevokedFalse(String jti);
}