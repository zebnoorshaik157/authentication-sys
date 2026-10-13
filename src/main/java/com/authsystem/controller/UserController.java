

package com.authsystem.controller;

import java.util.Map;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import com.authsystem.dto.LoginRequest;
import com.authsystem.dto.LoginResponse;
import com.authsystem.dto.RegisterRequest;
import com.authsystem.security.CookieService;
import com.authsystem.service.UserService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;

@RestController
public class UserController {

    private final UserService userService;
    private final CookieService cookieService;

    public UserController(
            UserService userService,
            CookieService cookieService) {
        this.userService = userService;
        this.cookieService = cookieService;
    }

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public String register(
            @Valid @RequestBody RegisterRequest request) {

        userService.registerUser(request);
        return "User registered successfully!";
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest) {

        LoginResponse loginResponse = userService.loginUser(request);

        HttpHeaders headers = new HttpHeaders();

        cookieService.addAuthCookies(
                httpRequest,
                headers,
                loginResponse.getAccessToken(),
                loginResponse.getRefreshToken());

        return new ResponseEntity<>(
                "Login successful",
                headers,
                HttpStatus.OK);
    }

    @PostMapping("/refresh")
    public ResponseEntity<String> refresh(
            @RequestBody(required = false) Map<String, String> request,
            HttpServletRequest httpRequest) {

        String refreshToken = cookieService.getCookieValue(
                httpRequest, "refreshToken");

        // First, try the refreshToken cookie.
        // If it is missing, support the older request-body approach.
        if (refreshToken == null || refreshToken.isBlank()) {
            if (request != null) {
                refreshToken = request.get("refreshToken");
            }
        }

        if (refreshToken == null || refreshToken.isBlank()) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Refresh token is required");
        }

        LoginResponse loginResponse =
                userService.refreshTokens(refreshToken);

        HttpHeaders headers = new HttpHeaders();

        cookieService.addAuthCookies(
                httpRequest,
                headers,
                loginResponse.getAccessToken(),
                loginResponse.getRefreshToken());

        return new ResponseEntity<>(
                "Tokens refreshed successfully",
                headers,
                HttpStatus.OK);
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout(
            @RequestBody(required = false) Map<String, String> request,
            HttpServletRequest httpRequest) {

        String refreshToken = cookieService.getCookieValue(
                httpRequest, "refreshToken");

        // First, try the refreshToken cookie.
        // If it is missing, support the older request-body approach.
        if (refreshToken == null || refreshToken.isBlank()) {
            if (request != null) {
                refreshToken = request.get("refreshToken");
            }
        }

        if (refreshToken == null || refreshToken.isBlank()) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Refresh token is required");
        }

        userService.logout(refreshToken);

        HttpHeaders headers = new HttpHeaders();

        cookieService.clearAuthCookies(httpRequest, headers);

        return new ResponseEntity<>(
                "Logged out successfully",
                headers,
                HttpStatus.OK);
    }
}
