
package com.authsystem.service;

import java.time.Instant;
import java.util.Locale;

import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import com.authsystem.dto.LoginRequest;
import com.authsystem.dto.LoginResponse;
import com.authsystem.dto.RegisterRequest;
import com.authsystem.entity.OAuthAccount;
import com.authsystem.entity.RefreshToken;
import com.authsystem.entity.User;
import com.authsystem.repository.OAuthAccountRepository;
import com.authsystem.repository.RefreshTokenRepository;
import com.authsystem.repository.UserRepository;
import com.authsystem.security.jwt.JwtService;

import io.jsonwebtoken.Claims;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final OAuthAccountRepository oauthAccountRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    public UserService(
            UserRepository userRepository,
            OAuthAccountRepository oauthAccountRepository,
            RefreshTokenRepository refreshTokenRepository,
            PasswordEncoder passwordEncoder,
            JwtService jwtService) {

        this.userRepository = userRepository;
        this.oauthAccountRepository = oauthAccountRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
    }

    @Transactional
    public void registerUser(RegisterRequest request) {

        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new ResponseStatusException(
                    HttpStatus.CONFLICT,
                    "Email already registered");
        }

        User user = new User();
        user.setName(request.getName());
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setRole("USER");

        userRepository.save(user);
    }

    @Transactional
    public LoginResponse loginUser(LoginRequest request) {

        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.UNAUTHORIZED,
                        "Invalid email or password"));

        if (user.getPassword() == null
                || !passwordEncoder.matches(
                        request.getPassword(), user.getPassword())) {
            throw new ResponseStatusException(
                    HttpStatus.UNAUTHORIZED,
                    "Invalid email or password");
        }

        return createLoginResponse(user);
    }

    /**
     * Authenticates an OAuth identity using its provider-issued stable ID.
     * Matching email alone never authenticates or links an existing user.
     */
    @Transactional
    public LoginResponse loginOrRegisterOAuthUser(
            String provider,
            String providerUserId,
            String email,
            String name) {

        String normalizedProvider = validateProviderIdentity(
                provider, providerUserId);

        if (email == null || email.isBlank()) {
            throw new ResponseStatusException(
                    HttpStatus.UNAUTHORIZED,
                    "OAuth account email is missing");
        }

        OAuthAccount existingOAuthAccount =
                oauthAccountRepository
                        .findByProviderAndProviderUserId(
                                normalizedProvider, providerUserId)
                        .orElse(null);

        if (existingOAuthAccount != null) {
            return createLoginResponse(existingOAuthAccount.getUser());
        }

        if (userRepository.findByEmail(email).isPresent()) {
            throw new ResponseStatusException(
                    HttpStatus.CONFLICT,
                    "An account with this email already exists. "
                            + "Sign in using the existing account.");
        }

        User user = new User();
        user.setEmail(email);
        user.setName(name == null || name.isBlank() ? email : name);
        user.setPassword(null);
        user.setRole("USER");

        User savedUser = userRepository.save(user);

        OAuthAccount oauthAccount = new OAuthAccount();
        oauthAccount.setProvider(normalizedProvider);
        oauthAccount.setProviderUserId(providerUserId);
        oauthAccount.setUser(savedUser);

        oauthAccountRepository.save(oauthAccount);

        return createLoginResponse(savedUser);
    }

    /**
     * Links a verified provider identity to an existing application user.
     *
     * IMPORTANT:
     * Call this only after the OAuth callback has been validated and the
     * target user has been obtained from trusted authentication/linking state.
     * Never pass the target email directly from an untrusted request body.
     */
    @Transactional
    public void linkOAuthAccount(
            String authenticatedUserEmail,
            String provider,
            String providerUserId) {

        if (authenticatedUserEmail == null
                || authenticatedUserEmail.isBlank()) {
            throw new ResponseStatusException(
                    HttpStatus.UNAUTHORIZED,
                    "You must sign in before linking an account");
        }

        String normalizedProvider = validateProviderIdentity(
                provider, providerUserId);

        User authenticatedUser = userRepository
                .findByEmail(authenticatedUserEmail)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.UNAUTHORIZED,
                        "Authenticated user was not found"));

        OAuthAccount existingLink = oauthAccountRepository
                .findByProviderAndProviderUserId(
                        normalizedProvider, providerUserId)
                .orElse(null);

        if (existingLink != null) {

            if (existingLink.getUser().getId()
                    .equals(authenticatedUser.getId())) {
                throw new ResponseStatusException(
                        HttpStatus.CONFLICT,
                        "This provider account is already linked");
            }

            throw new ResponseStatusException(
                    HttpStatus.CONFLICT,
                    "This provider account is linked to another user");
        }

        OAuthAccount oauthAccount = new OAuthAccount();
        oauthAccount.setProvider(normalizedProvider);
        oauthAccount.setProviderUserId(providerUserId);
        oauthAccount.setUser(authenticatedUser);

        oauthAccountRepository.save(oauthAccount);
    }

    private String validateProviderIdentity(
            String provider,
            String providerUserId) {

        if (provider == null || provider.isBlank()
                || providerUserId == null || providerUserId.isBlank()) {
            throw new ResponseStatusException(
                    HttpStatus.UNAUTHORIZED,
                    "OAuth provider identity is missing");
        }

        String normalizedProvider =
                provider.trim().toLowerCase(Locale.ROOT);

        if (!"google".equals(normalizedProvider)
                && !"github".equals(normalizedProvider)) {
            throw new ResponseStatusException(
                    HttpStatus.UNAUTHORIZED,
                    "Unsupported OAuth provider");
        }

        return normalizedProvider;
    }

    @Transactional
    public LoginResponse refreshTokens(String refreshToken) {

        try {
            Claims claims = jwtService.extractAllClaims(refreshToken);

            if (!"refresh".equals(
                    claims.get("tokenType", String.class))) {
                throw new ResponseStatusException(
                        HttpStatus.UNAUTHORIZED,
                        "Invalid refresh token");
            }

            String jti = claims.getId();

            if (jti == null || jti.isBlank()) {
                throw new ResponseStatusException(
                        HttpStatus.UNAUTHORIZED,
                        "Invalid refresh token");
            }

            RefreshToken storedToken =
                    refreshTokenRepository.findActiveTokenForUpdate(jti)
                            .orElseThrow(() -> new ResponseStatusException(
                                    HttpStatus.UNAUTHORIZED,
                                    "Refresh token is invalid or revoked"));

            if (storedToken.getExpiresAt().isBefore(Instant.now())) {
                storedToken.setRevoked(true);

                throw new ResponseStatusException(
                        HttpStatus.UNAUTHORIZED,
                        "Refresh token expired");
            }

            String email = claims.getSubject();

            if (email == null
                    || !storedToken.getUser().getEmail().equals(email)) {
                throw new ResponseStatusException(
                        HttpStatus.UNAUTHORIZED,
                        "Invalid refresh token");
            }

            User user = storedToken.getUser();

            storedToken.setRevoked(true);

            String newAccessToken = jwtService.generateToken(email);
            String newRefreshToken =
                    jwtService.generateRefreshToken(email);

            saveRefreshToken(user, newRefreshToken);

            return new LoginResponse(newAccessToken, newRefreshToken);

        } catch (ResponseStatusException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new ResponseStatusException(
                    HttpStatus.UNAUTHORIZED,
                    "Invalid or expired refresh token");
        }
    }

    private LoginResponse createLoginResponse(User user) {

        String accessToken = jwtService.generateToken(user.getEmail());
        String refreshToken =
                jwtService.generateRefreshToken(user.getEmail());

        saveRefreshToken(user, refreshToken);

        return new LoginResponse(accessToken, refreshToken);
    }

    private void saveRefreshToken(User user, String refreshToken) {

        RefreshToken tokenEntity = new RefreshToken();

        tokenEntity.setUser(user);
        tokenEntity.setJti(jwtService.extractJti(refreshToken));
        tokenEntity.setExpiresAt(
                jwtService.extractExpiration(refreshToken).toInstant());
        tokenEntity.setRevoked(false);

        refreshTokenRepository.save(tokenEntity);
    }

    @Transactional
    public void logout(String refreshToken) {

        try {
            Claims claims = jwtService.extractAllClaims(refreshToken);

            if (!"refresh".equals(
                    claims.get("tokenType", String.class))) {
                throw new ResponseStatusException(
                        HttpStatus.UNAUTHORIZED,
                        "Invalid refresh token");
            }

            String jti = claims.getId();

            if (jti == null || jti.isBlank()) {
                throw new ResponseStatusException(
                        HttpStatus.UNAUTHORIZED,
                        "Invalid refresh token");
            }

            RefreshToken storedToken =
                    refreshTokenRepository.findByJtiAndRevokedFalse(jti)
                            .orElseThrow(() -> new ResponseStatusException(
                                    HttpStatus.UNAUTHORIZED,
                                    "Refresh token is invalid or already revoked"));

            if (storedToken.getExpiresAt().isBefore(Instant.now())) {
                throw new ResponseStatusException(
                        HttpStatus.UNAUTHORIZED,
                        "Refresh token expired");
            }

            storedToken.setRevoked(true);
            refreshTokenRepository.save(storedToken);

        } catch (ResponseStatusException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new ResponseStatusException(
                    HttpStatus.UNAUTHORIZED,
                    "Invalid or expired refresh token");
        }
    }
}
