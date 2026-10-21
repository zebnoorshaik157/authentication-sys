
package com.authsystem.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.authsystem.entity.OAuthAccount;

public interface OAuthAccountRepository
        extends JpaRepository<OAuthAccount, Long> {

    Optional<OAuthAccount> findByProviderAndProviderUserId(
            String provider,
            String providerUserId);

    boolean existsByProviderAndProviderUserId(
            String provider,
            String providerUserId);
}
