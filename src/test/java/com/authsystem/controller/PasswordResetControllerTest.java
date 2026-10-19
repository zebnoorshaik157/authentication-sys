
package com.authsystem.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.mock;

import java.util.Map;

import jakarta.validation.Validation;
import jakarta.validation.Validator;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import com.authsystem.service.PasswordResetService;

class PasswordResetControllerTest {

    private PasswordResetService passwordResetService;
    private PasswordResetController controller;

    @BeforeEach
    void setUp() {
        passwordResetService = mock(PasswordResetService.class);
        controller = new PasswordResetController(passwordResetService);
    }

    @Test
    void forgotPasswordShouldReturnGenericMessage() {
        var request =
                new PasswordResetController.ForgotPasswordRequest(
                        "test@example.com");

        ResponseEntity<Map<String, String>> response =
                controller.forgotPassword(request);

        assertEquals(HttpStatus.OK, response.getStatusCode());

        assertEquals(
                "If the account exists, a password reset OTP will be sent.",
                response.getBody().get("message"));

        verify(passwordResetService)
                .forgotPassword("test@example.com");
    }

    @Test
    void verifyOtpShouldReturnResetToken() {
        var request =
                new PasswordResetController.VerifyOtpRequest(
                        "test@example.com", "123456");

        when(passwordResetService.verifyOtp(
                "test@example.com", "123456"))
                .thenReturn("test-reset-token");

        ResponseEntity<Map<String, String>> response =
                controller.verifyOtp(request);

        assertEquals(HttpStatus.OK, response.getStatusCode());

        assertEquals(
                "OTP verified successfully",
                response.getBody().get("message"));

        assertEquals(
                "test-reset-token",
                response.getBody().get("resetToken"));
    }

    @Test
    void resetPasswordShouldReturnSuccessMessage() {
        var request =
                new PasswordResetController.ResetPasswordRequest(
                        "test-reset-token", "NewPassword123!");

        ResponseEntity<Map<String, String>> response =
                controller.resetPassword(request);

        assertEquals(HttpStatus.OK, response.getStatusCode());

        assertEquals(
                "Password reset successfully",
                response.getBody().get("message"));

        verify(passwordResetService).resetPassword(
                "test-reset-token", "NewPassword123!");
    }

    @Test
    void forgotPasswordRequestShouldRejectInvalidEmail() {
        var request =
                new PasswordResetController.ForgotPasswordRequest(
                        "not-an-email");

        Validator validator =
                Validation.buildDefaultValidatorFactory()
                        .getValidator();

        var violations = validator.validate(request);

        assertFalse(
                violations.isEmpty(),
                "Invalid email should produce a validation error");
    }
}
