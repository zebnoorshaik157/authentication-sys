
package com.authsystem.security;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Service;

import jakarta.servlet.http.HttpServletRequest;

@Service
public class CookieService {

    private static final String ACCESS_COOKIE = "accessToken";
    private static final String REFRESH_COOKIE = "refreshToken";

    public void addAuthCookies(
            HttpServletRequest request,
            HttpHeaders headers,
            String accessToken,
            String refreshToken) {

        boolean secure = request.isSecure();

        ResponseCookie accessCookie = ResponseCookie
                .from(ACCESS_COOKIE, accessToken)
                .httpOnly(true)
                .secure(secure)
                .path("/")
                .sameSite("Lax")
                .maxAge(15 * 60)
                .build();

        ResponseCookie refreshCookie = ResponseCookie
                .from(REFRESH_COOKIE, refreshToken)
                .httpOnly(true)
                .secure(secure)
                .path("/")
                .sameSite("Lax")
                .maxAge(7 * 24 * 60 * 60)
                .build();

        headers.add(
                HttpHeaders.SET_COOKIE,
                accessCookie.toString());

        headers.add(
                HttpHeaders.SET_COOKIE,
                refreshCookie.toString());
    }

    public void clearAuthCookies(
            HttpServletRequest request,
            HttpHeaders headers) {

        boolean secure = request.isSecure();

        ResponseCookie accessCookie = ResponseCookie
                .from(ACCESS_COOKIE, "")
                .httpOnly(true)
                .secure(secure)
                .path("/")
                .sameSite("Lax")
                .maxAge(0)
                .build();

        ResponseCookie refreshCookie = ResponseCookie
                .from(REFRESH_COOKIE, "")
                .httpOnly(true)
                .secure(secure)
                .path("/")
                .sameSite("Lax")
                .maxAge(0)
                .build();

        headers.add(
                HttpHeaders.SET_COOKIE,
                accessCookie.toString());

        headers.add(
                HttpHeaders.SET_COOKIE,
                refreshCookie.toString());
    }

    public String getCookieValue(
            HttpServletRequest request,
            String cookieName) {

        if (request.getCookies() == null) {
            return null;
        }

        for (var cookie : request.getCookies()) {
            if (cookieName.equals(cookie.getName())) {
                return cookie.getValue();
            }
        }

        return null;
    }
}
