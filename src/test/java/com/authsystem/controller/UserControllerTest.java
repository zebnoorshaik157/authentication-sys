
package com.authsystem.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.util.Map;

import jakarta.servlet.http.Cookie;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.server.ResponseStatusException;

import com.authsystem.dto.LoginRequest;
import com.authsystem.dto.LoginResponse;
import com.authsystem.dto.RegisterRequest;
import com.authsystem.security.CookieService;
import com.authsystem.service.UserService;

class UserControllerTest {

    private UserService userService;
    private CookieService cookieService;
    private UserController controller;
    private MockHttpServletRequest request;

    @BeforeEach
    void setUp() {
        userService = mock(UserService.class);
        cookieService = mock(CookieService.class);

        controller = new UserController(userService, cookieService);
        request = new MockHttpServletRequest();
    }

    @Test
    void registerShouldReturnCreatedMessage() {
        RegisterRequest registerRequest = new RegisterRequest();
        registerRequest.setName("Test User");
        registerRequest.setEmail("test@example.com");
        registerRequest.setPassword("Password123!");

        ResponseEntity<String> response = ResponseEntity
                .status(HttpStatus.CREATED)
                .body(controller.register(registerRequest));

        assertEquals(HttpStatus.CREATED, response.getStatusCode());
        assertEquals(
                "User registered successfully!",
                response.getBody());

        verify(userService).registerUser(registerRequest);
    }

    @Test
    void loginShouldReturnSuccessAndAddCookies() {
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail("test@example.com");
        loginRequest.setPassword("Password123!");

        LoginResponse loginResponse =
                new LoginResponse("access-token", "refresh-token");

        when(userService.loginUser(loginRequest))
                .thenReturn(loginResponse);

        ResponseEntity<String> response =
                controller.login(loginRequest, request);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("Login successful", response.getBody());

        verify(cookieService).addAuthCookies(
                eq(request),
                any(org.springframework.http.HttpHeaders.class),
                eq("access-token"),
                eq("refresh-token"));
    }

    @Test
    void refreshShouldUseRefreshTokenCookieFirst() {
        request.setCookies(new Cookie(
                "refreshToken", "cookie-refresh-token"));

        when(cookieService.getCookieValue(request, "refreshToken"))
                .thenReturn("cookie-refresh-token");

        when(userService.refreshTokens("cookie-refresh-token"))
                .thenReturn(new LoginResponse(
                        "new-access-token", "new-refresh-token"));

        ResponseEntity<String> response =
                controller.refresh(
                        Map.of("refreshToken", "body-refresh-token"),
                        request);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(
                "Tokens refreshed successfully",
                response.getBody());

        verify(userService).refreshTokens("cookie-refresh-token");
        verify(cookieService).addAuthCookies(
                eq(request),
                any(org.springframework.http.HttpHeaders.class),
                eq("new-access-token"),
                eq("new-refresh-token"));
    }

    @Test
    void refreshShouldUseBodyWhenCookieIsMissing() {
        when(cookieService.getCookieValue(request, "refreshToken"))
                .thenReturn(null);

        when(userService.refreshTokens("body-refresh-token"))
                .thenReturn(new LoginResponse(
                        "new-access-token", "new-refresh-token"));

        ResponseEntity<String> response =
                controller.refresh(
                        Map.of("refreshToken", "body-refresh-token"),
                        request);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        verify(userService).refreshTokens("body-refresh-token");
    }

    @Test
    void refreshShouldRejectMissingToken() {
        when(cookieService.getCookieValue(request, "refreshToken"))
                .thenReturn(null);

        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> controller.refresh(null, request));

        assertEquals(
                HttpStatus.BAD_REQUEST,
                exception.getStatusCode());

        verify(userService, never()).refreshTokens(anyString());
    }

    @Test
    void logoutShouldRevokeTokenAndClearCookies() {
        when(cookieService.getCookieValue(request, "refreshToken"))
                .thenReturn("refresh-token");

        ResponseEntity<String> response =
                controller.logout(null, request);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("Logged out successfully", response.getBody());

        verify(userService).logout("refresh-token");
        verify(cookieService).clearAuthCookies(
                eq(request),
                any(org.springframework.http.HttpHeaders.class));
    }

    @Test
    void logoutShouldRejectMissingToken() {
        when(cookieService.getCookieValue(request, "refreshToken"))
                .thenReturn(null);

        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> controller.logout(null, request));

        assertEquals(
                HttpStatus.BAD_REQUEST,
                exception.getStatusCode());

        verify(userService, never()).logout(anyString());
        verify(cookieService, never()).clearAuthCookies(
                any(),
                any());
    }
}
