
package com.authsystem.service;

import java.time.Instant;

import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import com.authsystem.dto.LoginRequest;
import com.authsystem.dto.LoginResponse;
import com.authsystem.dto.RegisterRequest;
import com.authsystem.entity.RefreshToken;
import com.authsystem.entity.User;
import com.authsystem.repository.RefreshTokenRepository;
import com.authsystem.repository.UserRepository;
import com.authsystem.security.jwt.JwtService;

import io.jsonwebtoken.Claims;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    public UserService(
            UserRepository userRepository,
            RefreshTokenRepository refreshTokenRepository,
            PasswordEncoder passwordEncoder,
            JwtService jwtService) {
        this.userRepository = userRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
    }

    @Transactional
    public void registerUser(RegisterRequest request) {
        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new ResponseStatusException(
                    HttpStatus.CONFLICT, "Email already registered");
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

        String accessToken = jwtService.generateToken(user.getEmail());
        String refreshToken =
                jwtService.generateRefreshToken(user.getEmail());

        saveRefreshToken(user, refreshToken);

        return new LoginResponse(accessToken, refreshToken);
    }

    @Transactional
    public LoginResponse loginOrRegisterOAuthUser(String email, String name) {
        if (email == null || email.isBlank()) {
            throw new ResponseStatusException(
                    HttpStatus.UNAUTHORIZED,
                    "OAuth account email is missing");
        }

        User user = userRepository.findByEmail(email)
                .orElseGet(() -> {
                    User newUser = new User();
                    newUser.setEmail(email);
                    newUser.setName(
                            name == null || name.isBlank() ? email : name);
                    newUser.setPassword(null);
                    newUser.setRole("USER");
                    return userRepository.save(newUser);
                });

        String accessToken = jwtService.generateToken(user.getEmail());
        String refreshToken =
                jwtService.generateRefreshToken(user.getEmail());

        saveRefreshToken(user, refreshToken);

        return new LoginResponse(accessToken, refreshToken);
    }

    @Transactional
    public LoginResponse refreshTokens(String refreshToken) {
        try {
            Claims claims = jwtService.extractAllClaims(refreshToken);

            if (!"refresh".equals(
                    claims.get("tokenType", String.class))) {
                throw new ResponseStatusException(
                        HttpStatus.UNAUTHORIZED, "Invalid refresh token");
            }

            String jti = claims.getId();

            if (jti == null || jti.isBlank()) {
                throw new ResponseStatusException(
                        HttpStatus.UNAUTHORIZED, "Invalid refresh token");
            }

            RefreshToken storedToken =
                    refreshTokenRepository.findActiveTokenForUpdate(jti)
                            .orElseThrow(() -> new ResponseStatusException(
                                    HttpStatus.UNAUTHORIZED,
                                    "Refresh token is invalid or revoked"));

            if (storedToken.getExpiresAt().isBefore(Instant.now())) {
                storedToken.setRevoked(true);

                throw new ResponseStatusException(
                        HttpStatus.UNAUTHORIZED, "Refresh token expired");
            }

            String email = claims.getSubject();

            if (email == null
                    || !storedToken.getUser().getEmail().equals(email)) {
                throw new ResponseStatusException(
                        HttpStatus.UNAUTHORIZED, "Invalid refresh token");
            }

            User user = storedToken.getUser();

            // Revoke the old token and rotate to a new token.
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
                        HttpStatus.UNAUTHORIZED, "Invalid refresh token");
            }

            String jti = claims.getId();

            if (jti == null || jti.isBlank()) {
                throw new ResponseStatusException(
                        HttpStatus.UNAUTHORIZED, "Invalid refresh token");
            }

            RefreshToken storedToken =
                    refreshTokenRepository.findByJtiAndRevokedFalse(jti)
                            .orElseThrow(() -> new ResponseStatusException(
                                    HttpStatus.UNAUTHORIZED,
                                    "Refresh token is invalid or already revoked"));

            if (storedToken.getExpiresAt().isBefore(Instant.now())) {
                throw new ResponseStatusException(
                        HttpStatus.UNAUTHORIZED, "Refresh token expired");
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
