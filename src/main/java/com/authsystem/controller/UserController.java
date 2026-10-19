
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

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;

@RestController
@Tag(name = "User Authentication", description = "Registration, login, token refresh, and logout APIs")
public class UserController {

    private final UserService userService;
    private final CookieService cookieService;

    public UserController(
            UserService userService,
            CookieService cookieService) {
        this.userService = userService;
        this.cookieService = cookieService;
    }

    @Operation(
            summary = "Register a new user",
            description = "Creates a user account after validating the supplied details.")
    @ApiResponses({
            @ApiResponse(responseCode = "201", description = "User registered successfully"),
            @ApiResponse(responseCode = "400", description = "Request validation failed"),
            @ApiResponse(responseCode = "409", description = "User already exists, if handled by the application")
    })
    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public String register(
            @Valid @RequestBody RegisterRequest request) {

        userService.registerUser(request);
        return "User registered successfully!";
    }

    @Operation(
            summary = "Log in",
            description = "Authenticates a user and returns access and refresh tokens in HTTP cookies.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Login successful"),
            @ApiResponse(responseCode = "400", description = "Request validation failed"),
            @ApiResponse(responseCode = "401", description = "Invalid credentials")
    })
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

    @Operation(
            summary = "Refresh authentication tokens",
            description = "Uses the refresh token cookie, or a request-body fallback, to issue rotated tokens.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Tokens refreshed successfully"),
            @ApiResponse(responseCode = "400", description = "Refresh token is missing"),
            @ApiResponse(responseCode = "401", description = "Refresh token is invalid, expired, or revoked"),
            @ApiResponse(responseCode = "403", description = "CSRF validation failed")
    })
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

    @Operation(
            summary = "Log out",
            description = "Revokes the refresh token and clears authentication cookies.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Logged out successfully"),
            @ApiResponse(responseCode = "400", description = "Refresh token is missing"),
            @ApiResponse(responseCode = "401", description = "Authentication token is invalid"),
            @ApiResponse(responseCode = "403", description = "CSRF validation failed")
    })
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
