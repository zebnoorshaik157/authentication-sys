
package com.authsystem.service;

import java.time.Instant;
import java.util.Date;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
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

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private OAuthAccountRepository oauthAccountRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtService jwtService;

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @InjectMocks
    private UserService userService;

    private User user;

    @BeforeEach
    void setUp() {
        user = new User();
        user.setId(1L);
        user.setName("Test User");
        user.setEmail("test@example.com");
        user.setPassword("encodedPassword");
        user.setRole("USER");
    }

    private void stubTokenCreation(String email) {
        when(jwtService.generateToken(email))
                .thenReturn("access-token");
        when(jwtService.generateRefreshToken(email))
                .thenReturn("refresh-token");
        when(jwtService.extractJti("refresh-token"))
                .thenReturn("refresh-jti");
        when(jwtService.extractExpiration("refresh-token"))
                .thenReturn(Date.from(Instant.now().plusSeconds(3600)));
    }

    @Test
    void registerUser_shouldSaveUserWhenEmailIsNew() {
        RegisterRequest request = new RegisterRequest();
        request.setName("Test User");
        request.setEmail("test@example.com");
        request.setPassword("password123");

        when(userRepository.findByEmail("test@example.com"))
                .thenReturn(Optional.empty());
        when(passwordEncoder.encode("password123"))
                .thenReturn("encodedPassword");
        when(userRepository.save(any(User.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        userService.registerUser(request);

        verify(userRepository).save(any(User.class));
    }

    @Test
    void registerUser_shouldRejectDuplicateEmail() {
        RegisterRequest request = new RegisterRequest();
        request.setName("Test User");
        request.setEmail("test@example.com");
        request.setPassword("password123");

        when(userRepository.findByEmail("test@example.com"))
                .thenReturn(Optional.of(user));

        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> userService.registerUser(request));

        assertEquals(HttpStatus.CONFLICT, exception.getStatusCode());
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void loginUser_shouldReturnTokensWhenCredentialsAreCorrect() {
        LoginRequest request = new LoginRequest();
        request.setEmail("test@example.com");
        request.setPassword("password123");

        when(userRepository.findByEmail("test@example.com"))
                .thenReturn(Optional.of(user));
        when(passwordEncoder.matches("password123", "encodedPassword"))
                .thenReturn(true);
        stubTokenCreation("test@example.com");

        LoginResponse response = userService.loginUser(request);

        assertNotNull(response);
        assertEquals("access-token", response.getAccessToken());
        assertEquals("refresh-token", response.getRefreshToken());

        verify(refreshTokenRepository).save(any(RefreshToken.class));
    }

    @Test
    void loginUser_shouldRejectUnknownEmail() {
        LoginRequest request = new LoginRequest();
        request.setEmail("unknown@example.com");
        request.setPassword("password123");

        when(userRepository.findByEmail("unknown@example.com"))
                .thenReturn(Optional.empty());

        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> userService.loginUser(request));

        assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatusCode());
    }

    @Test
    void loginUser_shouldRejectIncorrectPassword() {
        LoginRequest request = new LoginRequest();
        request.setEmail("test@example.com");
        request.setPassword("wrongPassword");

        when(userRepository.findByEmail("test@example.com"))
                .thenReturn(Optional.of(user));
        when(passwordEncoder.matches("wrongPassword", "encodedPassword"))
                .thenReturn(false);

        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> userService.loginUser(request));

        assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatusCode());
    }

    @Test
    void oauthLogin_shouldCreateUserAndIdentityForNewAccount() {
        when(oauthAccountRepository
                .findByProviderAndProviderUserId("google", "google-sub-123"))
                .thenReturn(Optional.empty());
        when(userRepository.findByEmail("new@example.com"))
                .thenReturn(Optional.empty());
        when(userRepository.save(any(User.class)))
                .thenAnswer(invocation -> {
                    User saved = invocation.getArgument(0);
                    saved.setId(2L);
                    return saved;
                });
        when(oauthAccountRepository.save(any(OAuthAccount.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        stubTokenCreation("new@example.com");

        LoginResponse response = userService.loginOrRegisterOAuthUser(
                "google",
                "google-sub-123",
                "new@example.com",
                "New User");

        assertEquals("access-token", response.getAccessToken());
        assertEquals("refresh-token", response.getRefreshToken());

        ArgumentCaptor<User> userCaptor =
                ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());

        User savedUser = userCaptor.getValue();
        assertEquals("new@example.com", savedUser.getEmail());
        assertEquals("New User", savedUser.getName());
        assertNull(savedUser.getPassword());
        assertEquals("USER", savedUser.getRole());

        ArgumentCaptor<OAuthAccount> accountCaptor =
                ArgumentCaptor.forClass(OAuthAccount.class);
        verify(oauthAccountRepository).save(accountCaptor.capture());

        OAuthAccount savedAccount = accountCaptor.getValue();
        assertEquals("google", savedAccount.getProvider());
        assertEquals("google-sub-123", savedAccount.getProviderUserId());
        assertSame(savedUser, savedAccount.getUser());

        verify(refreshTokenRepository).save(any(RefreshToken.class));
    }

    @Test
    void oauthLogin_shouldAuthenticateReturningProviderIdentity() {
        OAuthAccount account = new OAuthAccount();
        account.setProvider("google");
        account.setProviderUserId("google-sub-123");
        account.setUser(user);

        when(oauthAccountRepository
                .findByProviderAndProviderUserId("google", "google-sub-123"))
                .thenReturn(Optional.of(account));

        stubTokenCreation("test@example.com");

        LoginResponse response = userService.loginOrRegisterOAuthUser(
                "google",
                "google-sub-123",
                "test@example.com",
                "Test User");

        assertEquals("access-token", response.getAccessToken());
        assertEquals("refresh-token", response.getRefreshToken());

        verify(userRepository, never()).save(any(User.class));
        verify(oauthAccountRepository, never()).save(any(OAuthAccount.class));
        verify(refreshTokenRepository).save(any(RefreshToken.class));
    }

    @Test
    void oauthLogin_shouldRejectEmailMatchingExistingPasswordAccount() {
        when(oauthAccountRepository
                .findByProviderAndProviderUserId("google", "different-sub"))
                .thenReturn(Optional.empty());
        when(userRepository.findByEmail("test@example.com"))
                .thenReturn(Optional.of(user));

        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> userService.loginOrRegisterOAuthUser(
                        "google",
                        "different-sub",
                        "test@example.com",
                        "Test User"));

        assertEquals(HttpStatus.CONFLICT, exception.getStatusCode());

        verify(userRepository, never()).save(any(User.class));
        verify(oauthAccountRepository, never()).save(any(OAuthAccount.class));
        verify(jwtService, never()).generateToken(anyString());
    }

    @Test
    void oauthLogin_shouldRejectMissingProviderIdentity() {
        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> userService.loginOrRegisterOAuthUser(
                        "google", " ", "new@example.com", "New User"));

        assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatusCode());
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void oauthLogin_shouldRejectUnsupportedProvider() {
        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> userService.loginOrRegisterOAuthUser(
                        "facebook",
                        "facebook-123",
                        "new@example.com",
                        "New User"));

        assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatusCode());
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void refreshTokens_shouldRotateTokenWhenRefreshTokenIsValid() {
        String oldRefreshToken = "old-refresh-token";

        RefreshToken storedToken = new RefreshToken();
        storedToken.setUser(user);
        storedToken.setJti("old-jti");
        storedToken.setExpiresAt(Instant.now().plusSeconds(3600));
        storedToken.setRevoked(false);

        Claims claims = mock(Claims.class);

        when(jwtService.extractAllClaims(oldRefreshToken))
                .thenReturn(claims);
        when(claims.get("tokenType", String.class))
                .thenReturn("refresh");
        when(claims.getId()).thenReturn("old-jti");
        when(claims.getSubject()).thenReturn("test@example.com");
        when(refreshTokenRepository.findActiveTokenForUpdate("old-jti"))
                .thenReturn(Optional.of(storedToken));
        when(jwtService.generateToken("test@example.com"))
                .thenReturn("new-access-token");
        when(jwtService.generateRefreshToken("test@example.com"))
                .thenReturn("new-refresh-token");
        when(jwtService.extractJti("new-refresh-token"))
                .thenReturn("new-jti");
        when(jwtService.extractExpiration("new-refresh-token"))
                .thenReturn(Date.from(Instant.now().plusSeconds(3600)));

        LoginResponse response =
                userService.refreshTokens(oldRefreshToken);

        assertEquals("new-access-token", response.getAccessToken());
        assertEquals("new-refresh-token", response.getRefreshToken());
        assertTrue(storedToken.isRevoked());

        verify(refreshTokenRepository).save(any(RefreshToken.class));
    }

    @Test
    void refreshTokens_shouldRejectRevokedOrMissingToken() {
        String refreshToken = "invalid-refresh-token";
        Claims claims = mock(Claims.class);

        when(jwtService.extractAllClaims(refreshToken))
                .thenReturn(claims);
        when(claims.get("tokenType", String.class))
                .thenReturn("refresh");
        when(claims.getId()).thenReturn("missing-jti");
        when(refreshTokenRepository.findActiveTokenForUpdate("missing-jti"))
                .thenReturn(Optional.empty());

        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> userService.refreshTokens(refreshToken));

        assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatusCode());
    }

    @Test
    void refreshTokens_shouldRejectAccessToken() {
        String accessToken = "access-token";
        Claims claims = mock(Claims.class);

        when(jwtService.extractAllClaims(accessToken))
                .thenReturn(claims);
        when(claims.get("tokenType", String.class))
                .thenReturn("access");

        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> userService.refreshTokens(accessToken));

        assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatusCode());

        verify(refreshTokenRepository, never())
                .findActiveTokenForUpdate(anyString());
    }

    @Test
    void refreshTokens_shouldRejectExpiredRefreshToken() {
        String expiredRefreshToken = "expired-refresh-token";

        RefreshToken storedToken = new RefreshToken();
        storedToken.setUser(user);
        storedToken.setJti("expired-jti");
        storedToken.setExpiresAt(Instant.now().minusSeconds(60));
        storedToken.setRevoked(false);

        Claims claims = mock(Claims.class);

        when(jwtService.extractAllClaims(expiredRefreshToken))
                .thenReturn(claims);
        when(claims.get("tokenType", String.class))
                .thenReturn("refresh");
        when(claims.getId()).thenReturn("expired-jti");
        when(refreshTokenRepository.findActiveTokenForUpdate("expired-jti"))
                .thenReturn(Optional.of(storedToken));

        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> userService.refreshTokens(expiredRefreshToken));

        assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatusCode());
        assertTrue(storedToken.isRevoked());

        verify(refreshTokenRepository, never())
                .save(any(RefreshToken.class));
        verify(jwtService, never()).generateToken(anyString());
        verify(jwtService, never()).generateRefreshToken(anyString());
    }

    @Test
    void logout_shouldRevokeValidRefreshToken() {
        String refreshToken = "valid-refresh-token";

        RefreshToken storedToken = new RefreshToken();
        storedToken.setUser(user);
        storedToken.setJti("logout-jti");
        storedToken.setExpiresAt(Instant.now().plusSeconds(3600));
        storedToken.setRevoked(false);

        Claims claims = mock(Claims.class);

        when(jwtService.extractAllClaims(refreshToken))
                .thenReturn(claims);
        when(claims.get("tokenType", String.class))
                .thenReturn("refresh");
        when(claims.getId()).thenReturn("logout-jti");
        when(refreshTokenRepository.findByJtiAndRevokedFalse("logout-jti"))
                .thenReturn(Optional.of(storedToken));

        userService.logout(refreshToken);

        assertTrue(storedToken.isRevoked());
        verify(refreshTokenRepository).save(storedToken);
    }

    @Test
    void logout_shouldRejectAccessToken() {
        String accessToken = "access-token";
        Claims claims = mock(Claims.class);

        when(jwtService.extractAllClaims(accessToken))
                .thenReturn(claims);
        when(claims.get("tokenType", String.class))
                .thenReturn("access");

        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> userService.logout(accessToken));

        assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatusCode());

        verify(refreshTokenRepository, never())
                .findByJtiAndRevokedFalse(anyString());
        verify(refreshTokenRepository, never())
                .save(any(RefreshToken.class));
    }

    @Test
    void logout_shouldRejectMissingOrRevokedRefreshToken() {
        String refreshToken = "revoked-refresh-token";
        Claims claims = mock(Claims.class);

        when(jwtService.extractAllClaims(refreshToken))
                .thenReturn(claims);
        when(claims.get("tokenType", String.class))
                .thenReturn("refresh");
        when(claims.getId()).thenReturn("revoked-jti");
        when(refreshTokenRepository.findByJtiAndRevokedFalse("revoked-jti"))
                .thenReturn(Optional.empty());

        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> userService.logout(refreshToken));

        assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatusCode());

        verify(refreshTokenRepository, never())
                .save(any(RefreshToken.class));
    }

    @Test
    void logout_shouldRejectExpiredRefreshToken() {
        String refreshToken = "expired-refresh-token";

        RefreshToken storedToken = new RefreshToken();
        storedToken.setUser(user);
        storedToken.setJti("expired-logout-jti");
        storedToken.setExpiresAt(Instant.now().minusSeconds(60));
        storedToken.setRevoked(false);

        Claims claims = mock(Claims.class);

        when(jwtService.extractAllClaims(refreshToken))
                .thenReturn(claims);
        when(claims.get("tokenType", String.class))
                .thenReturn("refresh");
        when(claims.getId()).thenReturn("expired-logout-jti");
        when(refreshTokenRepository.findByJtiAndRevokedFalse(
                "expired-logout-jti"))
                .thenReturn(Optional.of(storedToken));

        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> userService.logout(refreshToken));

        assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatusCode());
        assertFalse(storedToken.isRevoked());

        verify(refreshTokenRepository, never())
                .save(any(RefreshToken.class));
    }
}
