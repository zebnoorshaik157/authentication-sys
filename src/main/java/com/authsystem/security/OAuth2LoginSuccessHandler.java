package com.authsystem.security;

import java.io.IOException;

import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import com.authsystem.dto.LoginResponse;
import com.authsystem.service.UserService;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class OAuth2LoginSuccessHandler
        implements AuthenticationSuccessHandler {

    private final UserService userService;
    private final CookieService cookieService;

    public OAuth2LoginSuccessHandler(
            UserService userService,
            CookieService cookieService) {
        this.userService = userService;
        this.cookieService = cookieService;
    }

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication)
            throws IOException, ServletException {

        OAuth2User oauthUser =
                (OAuth2User) authentication.getPrincipal();

        String registrationId = request.getRequestURI()
                .contains("/github")
                ? "github"
                : "google";

        String email = oauthUser.getAttribute("email");
        String name = oauthUser.getAttribute("name");

        if ("google".equals(registrationId)) {
            Boolean emailVerified =
                    oauthUser.getAttribute("email_verified");

            if (email == null || email.isBlank()
                    || !Boolean.TRUE.equals(emailVerified)) {
                response.sendError(
                        HttpServletResponse.SC_UNAUTHORIZED,
                        "Google account email is missing or not verified");
                return;
            }
        } else {
            // GitHub may not return an email in its profile.
            // Do not create an account without a verified email.
            if (email == null || email.isBlank()) {
                response.sendError(
                        HttpServletResponse.SC_UNAUTHORIZED,
                        "GitHub did not provide an email. "
                                + "Configure verified email retrieval.");
                return;
            }
        }

        LoginResponse tokens =
                userService.loginOrRegisterOAuthUser(email, name);

        HttpHeaders headers = new HttpHeaders();

        cookieService.addAuthCookies(
                request,
                headers,
                tokens.getAccessToken(),
                tokens.getRefreshToken());

        headers.forEach((headerName, values) ->
                values.forEach(value ->
                        response.addHeader(headerName, value)));

        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("text/plain");
        response.getWriter().write(
                "github".equals(registrationId)
                        ? "GitHub login successful"
                        : "Google login successful");
    }
}