
package com.authsystem.service;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Comparator;
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

        // Return silently for an unknown account to prevent
        // account enumeration.
        if (user == null) {
            return;
        }

        Instant now = Instant.now();

        List<PasswordResetOtp> oldOtps =
                otpRepository.findByUserAndUsedFalse(user);

        // Find the latest OTP creation time.
        Instant latestCreation = oldOtps.stream()
                .map(PasswordResetOtp::getCreatedAt)
                .filter(createdAt -> createdAt != null)
                .max(Instant::compareTo)
                .orElse(null);

        // Enforce the resend cooldown.
        if (latestCreation != null
                && latestCreation.plusSeconds(
                        RESEND_COOLDOWN_SECONDS).isAfter(now)) {

            log.info("Password reset resend cooldown active");
            return;
        }

        // Invalidate previous unused OTPs.
        for (PasswordResetOtp oldOtp : oldOtps) {
            oldOtp.setUsed(true);
        }

        otpRepository.saveAll(oldOtps);

        // Generate a cryptographically secure six-digit OTP.
        String otp = String.format(
                "%06d", secureRandom.nextInt(1_000_000));

        PasswordResetOtp resetOtp = new PasswordResetOtp();
        resetOtp.setUser(user);
        resetOtp.setOtpHash(passwordEncoder.encode(otp));
        resetOtp.setExpiresAt(
                now.plusSeconds(OTP_EXPIRY_MINUTES * 60L));
        resetOtp.setUsed(false);
        resetOtp.setFailedAttempts(0);

        otpRepository.saveAndFlush(resetOtp);

        log.info("Password reset OTP record created: id={}",
                resetOtp.getId());

        // Never log the actual OTP.
        if (environment.acceptsProfiles(Profiles.of("dev"))) {
            log.info(
                    "Password reset OTP generated for email={}",
                    user.getEmail());
        }

        emailService.sendEmail(
                user.getEmail(),
                "Password Reset OTP",
                "Your password reset OTP is: " + otp
                        + "\nIt expires in 5 minutes."
                        + "\nIf you did not request this, ignore this email.");
    }

    // Step 2: Verify OTP and issue a password-reset token.
    @Transactional(noRollbackFor = ResponseStatusException.class)
    public String verifyOtp(String email, String otp) {

        log.info("OTP verification started");

        User user = userRepository.findByEmail(email)
                .orElseThrow(this::invalidOtp);

        log.info("OTP verification: user found, email={}",
                user.getEmail());

        // Find unused OTP records for this exact user.
        List<PasswordResetOtp> activeOtps =
                otpRepository.findByUserAndUsedFalse(user);

        log.info(
                "Found {} unused OTP record(s) for user id={}",
                activeOtps.size(),
                user.getId());

        PasswordResetOtp resetOtp = activeOtps.stream()
                .max(Comparator.comparing(
                        PasswordResetOtp::getId))
                .orElseThrow(this::invalidOtp);

        log.info("OTP verification: record found, id={}",
                resetOtp.getId());

        Instant now = Instant.now();

        log.info(
                "Verifying OTP record id={}, attempts={}, used={}, expiresAt={}",
                resetOtp.getId(),
                resetOtp.getFailedAttempts(),
                resetOtp.isUsed(),
                resetOtp.getExpiresAt());

        // Reject expired OTPs.
        if (!resetOtp.getExpiresAt().isAfter(now)) {

            log.info("OTP expired for record id={}",
                    resetOtp.getId());

            resetOtp.setUsed(true);
            otpRepository.saveAndFlush(resetOtp);

            throw invalidOtp();
        }

        // Reject OTPs that have already reached the attempt limit.
        if (resetOtp.getFailedAttempts() >= MAX_OTP_ATTEMPTS) {

            log.info("OTP attempt limit reached for record id={}",
                    resetOtp.getId());

            resetOtp.setUsed(true);
            otpRepository.saveAndFlush(resetOtp);

            throw invalidOtp();
        }

        // Incorrect OTP: increment and persist the counter.
        if (!passwordEncoder.matches(otp, resetOtp.getOtpHash())) {

            int attempts = resetOtp.getFailedAttempts() + 1;
            resetOtp.setFailedAttempts(attempts);

            // Invalidate the OTP after the fifth incorrect attempt.
            if (attempts >= MAX_OTP_ATTEMPTS) {
                resetOtp.setUsed(true);
            }

            log.info(
                    "Incorrect OTP for record id={}; saving failedAttempts={}",
                    resetOtp.getId(),
                    attempts);

            otpRepository.saveAndFlush(resetOtp);

            log.info(
                    "OTP attempt counter flushed for record id={}",
                    resetOtp.getId());

            throw invalidOtp();
        }

        // Correct OTP: consume it.
        resetOtp.setUsed(true);
        otpRepository.saveAndFlush(resetOtp);

        // Generate a short-lived password-reset JWT.
        String resetToken =
                jwtService.generatePasswordResetToken(user.getEmail());

        Claims claims = jwtService.extractAllClaims(resetToken);

        PasswordResetToken tokenRecord = new PasswordResetToken();
        tokenRecord.setTokenId(claims.getId());
        tokenRecord.setExpiresAt(
                claims.getExpiration().toInstant());
        tokenRecord.setUsed(false);

        resetTokenRepository.save(tokenRecord);

        log.info("Password reset token created for user id={}",
                user.getId());

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

            // Store only the BCrypt hash of the new password.
            user.setPassword(
                    passwordEncoder.encode(newPassword));

            userRepository.save(user);

            // Revoke all active refresh tokens for this user.
            refreshTokenRepository
                    .revokeAllActiveTokensByUserId(user.getId());

            // Prevent password-reset token reuse.
            tokenRecord.setUsed(true);
            resetTokenRepository.save(tokenRecord);

            log.info("Password reset completed for user id={}",
                    user.getId());

        } catch (ResponseStatusException ex) {
            throw ex;
        } catch (Exception ex) {
            log.error(
                    "Password reset failed due to an unexpected error",
                    ex);

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
