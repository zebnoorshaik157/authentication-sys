
package com.authsystem.security;

import java.io.IOException;
import java.util.Locale;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

import com.authsystem.controller.OAuthAccountLinkController;
import com.authsystem.dto.LoginResponse;
import com.authsystem.service.UserService;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

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

        if (!(authentication instanceof OAuth2AuthenticationToken oauthToken)) {
            sendError(
                    response,
                    HttpStatus.UNAUTHORIZED,
                    "Invalid OAuth2 authentication");
            return;
        }

        OAuth2User oauthUser =
                (OAuth2User) oauthToken.getPrincipal();

        String provider = oauthToken
                .getAuthorizedClientRegistrationId()
                .toLowerCase(Locale.ROOT);

        String email = oauthUser.getAttribute("email");
        String name = oauthUser.getAttribute("name");
        String providerUserId;

        if ("google".equals(provider)) {

            Boolean emailVerified =
                    oauthUser.getAttribute("email_verified");

            if (email == null || email.isBlank()
                    || !Boolean.TRUE.equals(emailVerified)) {
                sendError(
                        response,
                        HttpStatus.UNAUTHORIZED,
                        "Google account email is missing or not verified");
                return;
            }

            providerUserId = oauthUser.getAttribute("sub");

        } else if ("github".equals(provider)) {

            if (email == null || email.isBlank()
                    || !Boolean.TRUE.equals(
                            oauthUser.getAttribute("email_verified"))) {
                sendError(
                        response,
                        HttpStatus.UNAUTHORIZED,
                        "GitHub did not provide a verified email");
                return;
            }

            Object githubId = oauthUser.getAttribute("id");

            providerUserId = githubId == null
                    ? null
                    : String.valueOf(githubId);

        } else {
            sendError(
                    response,
                    HttpStatus.UNAUTHORIZED,
                    "Unsupported OAuth2 provider");
            return;
        }

        if (providerUserId == null || providerUserId.isBlank()) {
            sendError(
                    response,
                    HttpStatus.UNAUTHORIZED,
                    "OAuth provider identity is missing");
            return;
        }

        // Check whether this callback belongs to an account-linking attempt.
        HttpSession session = request.getSession(false);

        String linkingEmail = null;
        boolean linkingAttempt = false;

        if (session != null) {
            Object savedEmail = session.getAttribute(
                    OAuthAccountLinkController.TARGET_EMAIL);

            Object savedState = session.getAttribute(
                    OAuthAccountLinkController.TARGET_STATE);

            String callbackState = request.getParameter("state");

            if (savedEmail instanceof String
                    && savedState instanceof String
                    && callbackState != null
                    && callbackState.equals(savedState)) {

                linkingEmail = (String) savedEmail;
                linkingAttempt = true;
            }

            // Always consume the stored linking intent once this callback
            // has been handled, so it cannot be reused later.
            session.removeAttribute(
                    OAuthAccountLinkController.TARGET_EMAIL);

            session.removeAttribute(
                    OAuthAccountLinkController.TARGET_STATE);
        }

        if (linkingAttempt) {
            try {
                userService.linkOAuthAccount(
                        linkingEmail,
                        provider,
                        providerUserId);

                response.setStatus(HttpServletResponse.SC_OK);
                response.setContentType("text/plain;charset=UTF-8");
                response.getWriter().write(
                        "OAuth account linked successfully. Provider: "
                                + provider);

            } catch (ResponseStatusException ex) {
                sendError(
                        response,
                        ex.getStatusCode(),
                        ex.getReason() == null
                                ? "OAuth account linking was rejected"
                                : ex.getReason());
            }

            // Do not create login cookies during account linking.
            return;
        }

        // Normal OAuth login behavior remains unchanged.
        final LoginResponse tokens;

        try {
            tokens = userService.loginOrRegisterOAuthUser(
                    provider,
                    providerUserId,
                    email,
                    name);

        } catch (ResponseStatusException ex) {
            sendError(
                    response,
                    ex.getStatusCode(),
                    ex.getReason() == null
                            ? "OAuth login was rejected"
                            : ex.getReason());
            return;
        }

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
        response.setContentType("text/plain;charset=UTF-8");
        response.getWriter().write(
                "OAuth login successful. Provider: " + provider);
    }

    private void sendError(
            HttpServletResponse response,
            HttpStatusCode status,
            String message) throws IOException {

        if (response.isCommitted()) {
            return;
        }

        response.resetBuffer();
        response.setStatus(status.value());
        response.setContentType("text/plain;charset=UTF-8");
        response.getWriter().write(message);
    }
}
