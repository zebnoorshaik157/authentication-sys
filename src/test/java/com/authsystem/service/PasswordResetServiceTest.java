
package com.authsystem.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import com.authsystem.entity.PasswordResetOtp;
import com.authsystem.entity.PasswordResetToken;
import com.authsystem.entity.User;
import com.authsystem.repository.PasswordResetOtpRepository;
import com.authsystem.repository.PasswordResetTokenRepository;
import com.authsystem.repository.RefreshTokenRepository;
import com.authsystem.repository.UserRepository;
import com.authsystem.security.jwt.JwtService;

import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.server.ResponseStatusException;

@ExtendWith(MockitoExtension.class)
class PasswordResetServiceTest {

    @Mock
    private PasswordResetOtpRepository otpRepository;

    @Mock
    private PasswordResetTokenRepository resetTokenRepository;

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private EmailService emailService;

    @Mock
    private JwtService jwtService;

    @Mock
    private Environment environment;

    @InjectMocks
    private PasswordResetService passwordResetService;

    private User user;

    @BeforeEach
    void setUp() {
        user = new User();
        user.setId(1L);
        user.setEmail("test@example.com");
        user.setPassword("old-hashed-password");
    }

    @Test
    void forgotPasswordShouldReturnWhenUserDoesNotExist() {
        when(userRepository.findByEmail("unknown@example.com"))
                .thenReturn(Optional.empty());

        assertDoesNotThrow(() ->
                passwordResetService.forgotPassword(
                        "unknown@example.com"));

        verifyNoInteractions(emailService);
        verify(otpRepository, never()).saveAndFlush(any());
    }

    @Test
    void forgotPasswordShouldCreateOtpAndSendEmail() {
        when(userRepository.findByEmail(user.getEmail()))
                .thenReturn(Optional.of(user));
        when(otpRepository.findByUserAndUsedFalse(user))
                .thenReturn(List.of());
        when(passwordEncoder.encode(anyString()))
                .thenReturn("hashed-otp");

        passwordResetService.forgotPassword(user.getEmail());

        verify(otpRepository).saveAll(List.of());
        verify(otpRepository).saveAndFlush(any(PasswordResetOtp.class));
        verify(emailService).sendEmail(
                eq(user.getEmail()),
                eq("Password Reset OTP"),
                contains("It expires in 5 minutes."));
    }

    @Test
    void forgotPasswordShouldRespectResendCooldown() {
        PasswordResetOtp existingOtp = new PasswordResetOtp();
        existingOtp.setCreatedAt(Instant.now());

        when(userRepository.findByEmail(user.getEmail()))
                .thenReturn(Optional.of(user));
        when(otpRepository.findByUserAndUsedFalse(user))
                .thenReturn(List.of(existingOtp));

        passwordResetService.forgotPassword(user.getEmail());

        verify(otpRepository, never())
                .saveAndFlush(any(PasswordResetOtp.class));
        verifyNoInteractions(emailService);
    }

    @Test
    void verifyOtpShouldRejectUnknownUser() {
        when(userRepository.findByEmail(user.getEmail()))
                .thenReturn(Optional.empty());

        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> passwordResetService.verifyOtp(
                        user.getEmail(), "123456"));

        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatusCode());
        verify(otpRepository, never()).findUnusedOtpsForUpdate(any());
    }

    @Test
    void verifyOtpShouldRejectWhenNoActiveOtpExists() {
        when(userRepository.findByEmail(user.getEmail()))
                .thenReturn(Optional.of(user));
        when(otpRepository.findUnusedOtpsForUpdate(user))
                .thenReturn(List.of());

        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> passwordResetService.verifyOtp(
                        user.getEmail(), "123456"));

        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatusCode());
    }

    @Test
    void verifyOtpShouldIncrementAttemptsForIncorrectOtp() {
        PasswordResetOtp otp = createActiveOtp();
        otp.setFailedAttempts(0);

        when(userRepository.findByEmail(user.getEmail()))
                .thenReturn(Optional.of(user));
        when(otpRepository.findUnusedOtpsForUpdate(user))
                .thenReturn(List.of(otp));
        when(passwordEncoder.matches("000000", "hashed-otp"))
                .thenReturn(false);

        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> passwordResetService.verifyOtp(
                        user.getEmail(), "000000"));

        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatusCode());
        assertEquals(1, otp.getFailedAttempts());
        assertFalse(otp.isUsed());
        verify(otpRepository).saveAndFlush(otp);
    }

    @Test
    void verifyOtpShouldInvalidateOtpAfterFifthIncorrectAttempt() {
        PasswordResetOtp otp = createActiveOtp();
        otp.setFailedAttempts(4);

        when(userRepository.findByEmail(user.getEmail()))
                .thenReturn(Optional.of(user));
        when(otpRepository.findUnusedOtpsForUpdate(user))
                .thenReturn(List.of(otp));
        when(passwordEncoder.matches("000000", "hashed-otp"))
                .thenReturn(false);

        assertThrows(
                ResponseStatusException.class,
                () -> passwordResetService.verifyOtp(
                        user.getEmail(), "000000"));

        assertEquals(5, otp.getFailedAttempts());
        assertTrue(otp.isUsed());
        verify(otpRepository).saveAndFlush(otp);
    }

    @Test
    void verifyOtpShouldRejectExpiredOtp() {
        PasswordResetOtp otp = createActiveOtp();
        otp.setExpiresAt(Instant.now().minusSeconds(60));

        when(userRepository.findByEmail(user.getEmail()))
                .thenReturn(Optional.of(user));
        when(otpRepository.findUnusedOtpsForUpdate(user))
                .thenReturn(List.of(otp));

        assertThrows(
                ResponseStatusException.class,
                () -> passwordResetService.verifyOtp(
                        user.getEmail(), "123456"));

        assertTrue(otp.isUsed());
        verify(otpRepository).saveAndFlush(otp);
    }

    @Test
    void resetPasswordShouldRejectWrongTokenType() {
        Claims claims = mock(Claims.class);

        when(jwtService.extractAllClaims("bad-token"))
                .thenReturn(claims);
        when(claims.get("tokenType", String.class))
                .thenReturn("access");

        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> passwordResetService.resetPassword(
                        "bad-token", "NewPassword123!"));

        assertEquals(
                HttpStatus.UNAUTHORIZED,
                exception.getStatusCode());
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void resetPasswordShouldRejectMissingTokenId() {
        Claims claims = mock(Claims.class);

        when(jwtService.extractAllClaims("reset-token"))
                .thenReturn(claims);
        when(claims.get("tokenType", String.class))
                .thenReturn("password_reset");
        when(claims.getId()).thenReturn(null);

        assertThrows(
                ResponseStatusException.class,
                () -> passwordResetService.resetPassword(
                        "reset-token", "NewPassword123!"));

        verify(resetTokenRepository, never()).findByTokenId(anyString());
    }

    @Test
    void resetPasswordShouldUpdatePasswordAndRevokeRefreshTokens() {
        String resetToken = "valid-reset-token";
        String tokenId = "reset-jti";
        String newPassword = "NewPassword123!";

        Claims claims = mock(Claims.class);
        PasswordResetToken tokenRecord = new PasswordResetToken();
        tokenRecord.setTokenId(tokenId);
        tokenRecord.setExpiresAt(Instant.now().plusSeconds(300));
        tokenRecord.setUsed(false);

        when(jwtService.extractAllClaims(resetToken))
                .thenReturn(claims);
        when(claims.get("tokenType", String.class))
                .thenReturn("password_reset");
        when(claims.getId()).thenReturn(tokenId);
        when(claims.getSubject()).thenReturn(user.getEmail());

        when(resetTokenRepository.findByTokenId(tokenId))
                .thenReturn(Optional.of(tokenRecord));
        when(userRepository.findByEmail(user.getEmail()))
                .thenReturn(Optional.of(user));
        when(passwordEncoder.encode(newPassword))
                .thenReturn("new-hashed-password");

        passwordResetService.resetPassword(resetToken, newPassword);

        assertEquals("new-hashed-password", user.getPassword());
        assertTrue(tokenRecord.isUsed());

        verify(userRepository).save(user);
        verify(refreshTokenRepository)
                .revokeAllActiveTokensByUserId(user.getId());
        verify(resetTokenRepository).save(tokenRecord);
    }

    @Test
    void resetPasswordShouldRejectAlreadyUsedToken() {
        String resetToken = "used-reset-token";
        String tokenId = "reset-jti";

        Claims claims = mock(Claims.class);
        PasswordResetToken tokenRecord = new PasswordResetToken();
        tokenRecord.setTokenId(tokenId);
        tokenRecord.setExpiresAt(Instant.now().plusSeconds(300));
        tokenRecord.setUsed(true);

        when(jwtService.extractAllClaims(resetToken))
                .thenReturn(claims);
        when(claims.get("tokenType", String.class))
                .thenReturn("password_reset");
        when(claims.getId()).thenReturn(tokenId);
        when(resetTokenRepository.findByTokenId(tokenId))
                .thenReturn(Optional.of(tokenRecord));

        assertThrows(
                ResponseStatusException.class,
                () -> passwordResetService.resetPassword(
                        resetToken, "NewPassword123!"));

        verify(userRepository, never()).save(any(User.class));
    }

    private PasswordResetOtp createActiveOtp() {
        PasswordResetOtp otp = new PasswordResetOtp();
        otp.setUser(user);
        otp.setOtpHash("hashed-otp");
        otp.setExpiresAt(Instant.now().plusSeconds(300));
        otp.setUsed(false);
        otp.setFailedAttempts(0);
        return otp;
    }
}
