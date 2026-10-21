package com.authsystem.controller;

import java.util.Locale;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

@RestController
@RequestMapping("/api/auth/oauth")
public class OAuthAccountLinkController {

    public static final String PENDING_EMAIL =
            "OAUTH_LINK_PENDING_EMAIL";

    public static final String PENDING_PROVIDER =
            "OAUTH_LINK_PENDING_PROVIDER";

    public static final String PENDING_TIME =
            "OAUTH_LINK_PENDING_TIME";

    public static final String TARGET_EMAIL =
            "OAUTH_LINK_TARGET_EMAIL";

    public static final String TARGET_STATE =
            "OAUTH_LINK_TARGET_STATE";

    @PostMapping("/link/{provider}")
    public Map<String, String> initiateLink(
            @PathVariable String provider,
            HttpServletRequest request) {

        Authentication authentication =
                SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null
                || !authentication.isAuthenticated()
                || authentication instanceof AnonymousAuthenticationToken) {
            throw new ResponseStatusException(
                    HttpStatus.UNAUTHORIZED,
                    "Sign in before linking an OAuth account");
        }

        String email = authentication.getName();

        if (email == null || email.isBlank()
                || "anonymousUser".equals(email)) {
            throw new ResponseStatusException(
                    HttpStatus.UNAUTHORIZED,
                    "Authenticated user identity is missing");
        }

        String normalizedProvider =
                provider.trim().toLowerCase(Locale.ROOT);

        if (!"google".equals(normalizedProvider)
                && !"github".equals(normalizedProvider)) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Provider must be google or github");
        }

        HttpSession session = request.getSession(true);

        // Clear any incomplete linking attempt in this browser session.
        session.removeAttribute(PENDING_EMAIL);
        session.removeAttribute(PENDING_PROVIDER);
        session.removeAttribute(PENDING_TIME);
        session.removeAttribute(TARGET_EMAIL);
        session.removeAttribute(TARGET_STATE);

        // Store the intended account, based on validated authentication.
        session.setAttribute(PENDING_EMAIL, email);
        session.setAttribute(PENDING_PROVIDER, normalizedProvider);
        session.setAttribute(PENDING_TIME, System.currentTimeMillis());

        return Map.of(
                "message", "Linking initiated. Open the authorization URL.",
                "authorizationUrl",
                request.getContextPath()
                        + "/oauth2/authorization/"
                        + normalizedProvider);
    }
}