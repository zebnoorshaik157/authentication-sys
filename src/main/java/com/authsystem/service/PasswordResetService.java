
package com.authsystem.service;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import com.authsystem.entity.PasswordResetOtp;
import com.authsystem.entity.PasswordResetToken;
import com.authsystem.entity.User;
import com.authsystem.repository.PasswordResetOtpRepository;
import com.authsystem.repository.PasswordResetTokenRepository;
import com.authsystem.repository.RefreshTokenRepository;
import com.authsystem.repository.UserRepository;
import com.authsystem.security.jwt.JwtService;

import io.jsonwebtoken.Claims;

@Service
public class PasswordResetService {

    private static final Logger log =
            LoggerFactory.getLogger(PasswordResetService.class);

    private static final int OTP_EXPIRY_MINUTES = 5;
    private static final int MAX_OTP_ATTEMPTS = 5;
    private static final int RESEND_COOLDOWN_SECONDS = 60;

    private final PasswordResetOtpRepository otpRepository;
    private final PasswordResetTokenRepository resetTokenRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;
    private final JwtService jwtService;
    private final Environment environment;

    private final SecureRandom secureRandom = new SecureRandom();

    public PasswordResetService(
            PasswordResetOtpRepository otpRepository,
            PasswordResetTokenRepository resetTokenRepository,
            RefreshTokenRepository refreshTokenRepository,
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            EmailService emailService,
            JwtService jwtService,
            Environment environment) {

        this.otpRepository = otpRepository;
        this.resetTokenRepository = resetTokenRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.emailService = emailService;
        this.jwtService = jwtService;
        this.environment = environment;
    }

    // Step 1: Generate and email an OTP.
    @Transactional
    public void forgotPassword(String email) {

        User user = userRepository.findByEmail(email).orElse(null);

        // Keep the response generic to prevent account enumeration.
        if (user == null) {
            return;
        }

        Instant now = Instant.now();

        List<PasswordResetOtp> oldOtps =
                otpRepository.findByUserAndUsedFalse(user);

        // Enforce resend cooldown using the latest OTP creation time.
        Instant latestCreation = oldOtps.stream()
                .map(PasswordResetOtp::getCreatedAt)
                .filter(createdAt -> createdAt != null)
                .max(Instant::compareTo)
                .orElse(null);

        if (latestCreation != null
                && latestCreation.plusSeconds(RESEND_COOLDOWN_SECONDS)
                        .isAfter(now)) {
            return;
        }

        // Invalidate any previous active OTPs.
        for (PasswordResetOtp oldOtp : oldOtps) {
            oldOtp.setUsed(true);
        }

        String otp = String.format(
                "%06d", secureRandom.nextInt(1_000_000));

        PasswordResetOtp resetOtp = new PasswordResetOtp();
        resetOtp.setUser(user);
        resetOtp.setOtpHash(passwordEncoder.encode(otp));
        resetOtp.setExpiresAt(
                now.plusSeconds(OTP_EXPIRY_MINUTES * 60L));
        resetOtp.setUsed(false);
        resetOtp.setFailedAttempts(0);

        otpRepository.save(resetOtp);

        // Development-only logging; never log OTPs in production.
        if (environment.acceptsProfiles(Profiles.of("dev"))) {
            log.warn(
                    "DEV ONLY: Password reset OTP generated for {}",
                    user.getEmail());
        }

        emailService.sendEmail(
                user.getEmail(),
                "Password Reset OTP",
                "Your password reset OTP is: " + otp
                        + "\nIt expires in 5 minutes."
                        + "\nIf you did not request this, ignore this email.");
    }

    // Step 2: Verify OTP and issue a reset token.
    @Transactional(noRollbackFor = ResponseStatusException.class)
    public String verifyOtp(String email, String otp) {

        User user = userRepository.findByEmail(email)
                .orElseThrow(this::invalidOtp);

        PasswordResetOtp resetOtp = otpRepository
                .findTopByUserAndUsedFalseOrderByIdDesc(user)
                .orElseThrow(this::invalidOtp);

        Instant now = Instant.now();

        if (resetOtp.isUsed()
                || !resetOtp.getExpiresAt().isAfter(now)) {
            resetOtp.setUsed(true);
            otpRepository.save(resetOtp);
            throw invalidOtp();
        }

        if (resetOtp.getFailedAttempts() >= MAX_OTP_ATTEMPTS) {
            resetOtp.setUsed(true);
            otpRepository.save(resetOtp);
            throw invalidOtp();
        }

        if (!passwordEncoder.matches(otp, resetOtp.getOtpHash())) {

            int attempts = resetOtp.getFailedAttempts() + 1;
            resetOtp.setFailedAttempts(attempts);

            if (attempts >= MAX_OTP_ATTEMPTS) {
                resetOtp.setUsed(true);
            }

            otpRepository.saveAndFlush(resetOtp);
            throw invalidOtp();
        }

        resetOtp.setUsed(true);
        otpRepository.save(resetOtp);

        String resetToken =
                jwtService.generatePasswordResetToken(user.getEmail());

        Claims claims = jwtService.extractAllClaims(resetToken);

        PasswordResetToken tokenRecord = new PasswordResetToken();
        tokenRecord.setTokenId(claims.getId());
        tokenRecord.setExpiresAt(
                claims.getExpiration().toInstant());
        tokenRecord.setUsed(false);

        resetTokenRepository.save(tokenRecord);

        return resetToken;
    }

    // Step 3: Change password and revoke active refresh tokens.
    @Transactional
    public void resetPassword(
            String resetToken, String newPassword) {

        try {
            Claims claims =
                    jwtService.extractAllClaims(resetToken);

            if (!"password_reset".equals(
                    claims.get("tokenType", String.class))) {
                throw invalidResetToken();
            }

            String tokenId = claims.getId();

            if (tokenId == null) {
                throw invalidResetToken();
            }

            PasswordResetToken tokenRecord = resetTokenRepository
                    .findByTokenId(tokenId)
                    .orElseThrow(this::invalidResetToken);

            if (tokenRecord.isUsed()
                    || !tokenRecord.getExpiresAt()
                            .isAfter(Instant.now())) {
                throw invalidResetToken();
            }

            String email = claims.getSubject();

            User user = userRepository.findByEmail(email)
                    .orElseThrow(this::invalidResetToken);

            user.setPassword(
                    passwordEncoder.encode(newPassword));
            userRepository.save(user);

            // Revoke all active refresh tokens for this user.
            refreshTokenRepository
                    .revokeAllActiveTokensByUserId(user.getId());

            // Prevent reuse of the reset token.
            tokenRecord.setUsed(true);
            resetTokenRepository.save(tokenRecord);

        } catch (ResponseStatusException ex) {
            throw ex;
        } catch (Exception ex) {
            throw invalidResetToken();
        }
    }

    private ResponseStatusException invalidOtp() {
        return new ResponseStatusException(
                HttpStatus.BAD_REQUEST,
                "Invalid or expired OTP");
    }

    private ResponseStatusException invalidResetToken() {
        return new ResponseStatusException(
                HttpStatus.UNAUTHORIZED,
                "Invalid or expired password reset token");
    }
}
