package com.authsystem.controller;

import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.authsystem.dto.LoginRequest;
import com.authsystem.dto.LoginResponse;
import com.authsystem.dto.RegisterRequest;
import com.authsystem.service.UserService;

@RestController
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public String register(@RequestBody RegisterRequest request) {
        userService.registerUser(request);
        return "User registered successfully!";
    }

    @PostMapping("/login")
    public LoginResponse login(@RequestBody LoginRequest request) {
        return userService.loginUser(request);
    }

    @PostMapping("/refresh")
    public LoginResponse refresh(@RequestBody Map<String, String> request) {
        String refreshToken = request.get("refreshToken");

        if (refreshToken == null || refreshToken.isBlank()) {
            throw new org.springframework.web.server.ResponseStatusException(
                    HttpStatus.BAD_REQUEST, "Refresh token is required");
        }

        return userService.refreshTokens(refreshToken);
    }
    @PostMapping("/logout")
public org.springframework.http.ResponseEntity<String> logout(
        @RequestBody Map<String, String> request) {

    String refreshToken = request.get("refreshToken");

    if (refreshToken == null || refreshToken.isBlank()) {
        throw new org.springframework.web.server.ResponseStatusException(
                HttpStatus.BAD_REQUEST,
                "Refresh token is required");
    }

    userService.logout(refreshToken);

    return org.springframework.http.ResponseEntity.ok(
            "Logged out successfully");
}
}