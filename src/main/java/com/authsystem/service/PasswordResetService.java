
package com.authsystem.service;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import com.authsystem.entity.PasswordResetOtp;
import com.authsystem.entity.User;
import com.authsystem.repository.PasswordResetOtpRepository;
import com.authsystem.repository.UserRepository;
import com.authsystem.security.jwt.JwtService;

import io.jsonwebtoken.Claims;

@Service
public class PasswordResetService {

    private static final int OTP_EXPIRY_MINUTES = 5;

    private final PasswordResetOtpRepository otpRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;
    private final JwtService jwtService;

    private final SecureRandom secureRandom = new SecureRandom();

    public PasswordResetService(
            PasswordResetOtpRepository otpRepository,
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            EmailService emailService,
            JwtService jwtService) {

        this.otpRepository = otpRepository;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.emailService = emailService;
        this.jwtService = jwtService;
    }

    // Step 1: Generate and email an OTP
    @Transactional
    public void forgotPassword(String email) {

        User user = userRepository.findByEmail(email).orElse(null);

        // Do not reveal whether the email exists
        if (user == null) {
            return;
        }

        List<PasswordResetOtp> oldOtps =
                otpRepository.findByUserAndUsedFalse(user);

        for (PasswordResetOtp oldOtp : oldOtps) {
            oldOtp.setUsed(true);
        }

        String otp = String.format(
                "%06d", secureRandom.nextInt(1_000_000));

        PasswordResetOtp resetOtp = new PasswordResetOtp();
        resetOtp.setUser(user);
        resetOtp.setOtpHash(passwordEncoder.encode(otp));
        resetOtp.setExpiresAt(
                Instant.now().plusSeconds(OTP_EXPIRY_MINUTES * 60L));
        resetOtp.setUsed(false);

        otpRepository.save(resetOtp);

        emailService.sendEmail(
                user.getEmail(),
                "Password Reset OTP",
                "Your password reset OTP is: " + otp
                        + "\nIt expires in 5 minutes."
                        + "\nIf you did not request this, ignore this email.");
    }

    // Step 2: Verify OTP and return a reset token
    @Transactional
    public String verifyOtp(String email, String otp) {

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> invalidOtp());

        PasswordResetOtp resetOtp = otpRepository
                .findTopByUserAndUsedFalseOrderByIdDesc(user)
                .orElseThrow(() -> invalidOtp());

        if (resetOtp.getExpiresAt().isBefore(Instant.now())
                || !passwordEncoder.matches(
                        otp, resetOtp.getOtpHash())) {
            throw invalidOtp();
        }

        resetOtp.setUsed(true);
        otpRepository.save(resetOtp);

        return jwtService.generatePasswordResetToken(user.getEmail());
    }

    // Step 3: Validate reset token and save the new password
    @Transactional
    public void resetPassword(String resetToken, String newPassword) {

        try {
            Claims claims = jwtService.extractAllClaims(resetToken);

            if (!"password_reset".equals(
                    claims.get("tokenType", String.class))) {
                throw invalidResetToken();
            }

            String email = claims.getSubject();

            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> invalidResetToken());

            user.setPassword(passwordEncoder.encode(newPassword));
            userRepository.save(user);

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
