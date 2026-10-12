
package com.authsystem.controller;

import java.util.Map;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.authsystem.service.PasswordResetService;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/auth")
public class PasswordResetController {

    private final PasswordResetService passwordResetService;

    public PasswordResetController(
            PasswordResetService passwordResetService) {
        this.passwordResetService = passwordResetService;
    }

    public record ForgotPasswordRequest(
            @NotBlank @Email String email) {
    }

    public record VerifyOtpRequest(
            @NotBlank @Email String email,
            @NotBlank @Size(min = 6, max = 6) String otp) {
    }

    public record ResetPasswordRequest(
            @NotBlank String resetToken,
            @NotBlank @Size(min = 8) String newPassword) {
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<Map<String, String>> forgotPassword(
            @Valid @RequestBody ForgotPasswordRequest request) {

        passwordResetService.forgotPassword(request.email());

        return ResponseEntity.ok(Map.of(
                "message",
                "If the account exists, a password reset OTP will be sent."));
    }

    @PostMapping("/verify-otp")
    public ResponseEntity<Map<String, String>> verifyOtp(
            @Valid @RequestBody VerifyOtpRequest request) {

        String resetToken = passwordResetService.verifyOtp(
                request.email(), request.otp());

        return ResponseEntity.ok(Map.of(
                "message", "OTP verified successfully",
                "resetToken", resetToken));
    }

    @PostMapping("/reset-password")
    public ResponseEntity<Map<String, String>> resetPassword(
            @Valid @RequestBody ResetPasswordRequest request) {

        passwordResetService.resetPassword(
                request.resetToken(), request.newPassword());

        return ResponseEntity.ok(Map.of(
                "message", "Password reset successfully"));
    }
}
