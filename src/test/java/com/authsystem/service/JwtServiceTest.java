
package com.authsystem.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Base64;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

class JwtServiceTest {

    private JwtService jwtService;

    private static final String EMAIL = "test@example.com";

    private static final String SECRET = Base64.getEncoder()
            .encodeToString(
                    "0123456789012345678901234567890123456789012345678901234567890123"
                            .getBytes());

    @BeforeEach
    void setUp() {
        jwtService = new JwtService();

        ReflectionTestUtils.setField(
                jwtService, "secret", SECRET);
    }

    @Test
    void generateToken_shouldCreateValidAccessToken() {
        String token = jwtService.generateToken(EMAIL);

        assertNotNull(token);
        assertTrue(jwtService.isTokenValid(token, EMAIL));
    }

    @Test
    void generateToken_shouldContainCorrectClaims() {
        String token = jwtService.generateToken(EMAIL);

        Claims claims = jwtService.extractAllClaims(token);

        assertEquals(EMAIL, claims.getSubject());
        assertEquals("access",
                claims.get("tokenType", String.class));
        assertNotNull(claims.getIssuedAt());
        assertNotNull(claims.getExpiration());
        assertNull(claims.getId());
    }

    @Test
    void generateToken_shouldExpireAfterApproximately15Minutes() {
        long beforeGeneration = System.currentTimeMillis();

        String token = jwtService.generateToken(EMAIL);

        long afterGeneration = System.currentTimeMillis();

        Date expiration = jwtService.extractExpiration(token);
        long expectedDuration = 15 * 60 * 1000L;

        assertTrue(
                expiration.getTime()
                        >= beforeGeneration + expectedDuration - 1000,
                "Access token expiration is earlier than expected");

        assertTrue(
                expiration.getTime()
                        <= afterGeneration + expectedDuration,
                "Access token expiration is later than expected");
    }

    @Test
    void generateRefreshToken_shouldContainCorrectClaimsAndUniqueJti() {
        String firstToken = jwtService.generateRefreshToken(EMAIL);
        String secondToken = jwtService.generateRefreshToken(EMAIL);

        Claims firstClaims = jwtService.extractAllClaims(firstToken);
        Claims secondClaims = jwtService.extractAllClaims(secondToken);

        assertEquals(EMAIL, firstClaims.getSubject());
        assertEquals("refresh",
                firstClaims.get("tokenType", String.class));

        assertNotNull(firstClaims.getId());
        assertNotNull(secondClaims.getId());
        assertNotEquals(firstClaims.getId(), secondClaims.getId());
    }

    @Test
    void generateRefreshToken_shouldExpireAfterApproximately7Days() {
        long beforeGeneration = System.currentTimeMillis();

        String token = jwtService.generateRefreshToken(EMAIL);

        long afterGeneration = System.currentTimeMillis();

        Date expiration = jwtService.extractExpiration(token);
        long sevenDays = 7L * 24 * 60 * 60 * 1000;

        assertTrue(
                expiration.getTime()
                        >= beforeGeneration + sevenDays - 1000,
                "Refresh token expiration is earlier than expected");

        assertTrue(
                expiration.getTime()
                        <= afterGeneration + sevenDays,
                "Refresh token expiration is later than expected");
    }

    @Test
    void generatePasswordResetToken_shouldContainCorrectClaimsAndUniqueJti() {
        String firstToken =
                jwtService.generatePasswordResetToken(EMAIL);
        String secondToken =
                jwtService.generatePasswordResetToken(EMAIL);

        Claims firstClaims = jwtService.extractAllClaims(firstToken);
        Claims secondClaims = jwtService.extractAllClaims(secondToken);

        assertEquals(EMAIL, firstClaims.getSubject());
        assertEquals("password_reset",
                firstClaims.get("tokenType", String.class));

        assertNotNull(firstClaims.getId());
        assertNotNull(secondClaims.getId());
        assertNotEquals(firstClaims.getId(), secondClaims.getId());
    }

    @Test
    void generatePasswordResetToken_shouldExpireAfterApproximately10Minutes() {
        long beforeGeneration = System.currentTimeMillis();

        String token = jwtService.generatePasswordResetToken(EMAIL);

        long afterGeneration = System.currentTimeMillis();

        Date expiration = jwtService.extractExpiration(token);
        long tenMinutes = 10 * 60 * 1000L;

        assertTrue(
                expiration.getTime()
                        >= beforeGeneration + tenMinutes - 1000,
                "Password reset token expiration is earlier than expected");

        assertTrue(
                expiration.getTime()
                        <= afterGeneration + tenMinutes,
                "Password reset token expiration is later than expected");
    }

    @Test
    void extractEmail_shouldReturnTokenSubject() {
        String token = jwtService.generateToken(EMAIL);

        assertEquals(EMAIL, jwtService.extractEmail(token));
    }

    @Test
    void extractJti_shouldReturnRefreshTokenId() {
        String token = jwtService.generateRefreshToken(EMAIL);

        assertNotNull(jwtService.extractJti(token));
        assertEquals(
                jwtService.extractJti(token),
                jwtService.extractAllClaims(token).getId());
    }

    @Test
    void extractExpiration_shouldReturnTokenExpiration() {
        String token = jwtService.generateToken(EMAIL);

        assertEquals(
                jwtService.extractAllClaims(token).getExpiration(),
                jwtService.extractExpiration(token));
    }

    @Test
    void isTokenValid_shouldReturnTrueForCorrectEmailAndAccessToken() {
        String token = jwtService.generateToken(EMAIL);

        assertTrue(jwtService.isTokenValid(token, EMAIL));
    }

    @Test
    void isTokenValid_shouldReturnFalseForDifferentEmail() {
        String token = jwtService.generateToken(EMAIL);

        assertFalse(
                jwtService.isTokenValid(token, "other@example.com"));
    }

    @Test
    void isTokenValid_shouldReturnFalseForNullEmail() {
        String token = jwtService.generateToken(EMAIL);

        assertFalse(jwtService.isTokenValid(token, null));
    }

    @Test
    void isTokenValid_shouldReturnFalseForRefreshToken() {
        String token = jwtService.generateRefreshToken(EMAIL);

        assertFalse(jwtService.isTokenValid(token, EMAIL));
    }

    @Test
    void isTokenValid_shouldReturnFalseForPasswordResetToken() {
        String token = jwtService.generatePasswordResetToken(EMAIL);

        assertFalse(jwtService.isTokenValid(token, EMAIL));
    }

    @Test
    void isTokenValid_shouldReturnFalseForMalformedToken() {
        assertFalse(
                jwtService.isTokenValid("invalid.token.value", EMAIL));
    }

    @Test
    void extractAllClaims_shouldRejectTokenSignedWithDifferentKey() {
        String token = jwtService.generateToken(EMAIL);

        JwtService anotherService = new JwtService();

        String differentSecret = Base64.getEncoder()
                .encodeToString(
                        "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                .getBytes());

        ReflectionTestUtils.setField(
                anotherService, "secret", differentSecret);

        assertThrows(
                Exception.class,
                () -> anotherService.extractAllClaims(token));
    }

    @Test
    void extractAllClaims_shouldRejectExpiredToken() {
        long now = System.currentTimeMillis();

        Date issuedAt = new Date(now - 120_000);
        Date expiredAt = new Date(now - 60_000);

        String expiredToken = Jwts.builder()
                .subject(EMAIL)
                .claim("tokenType", "access")
                .issuedAt(issuedAt)
                .expiration(expiredAt)
                .signWith(
                        io.jsonwebtoken.security.Keys.hmacShaKeyFor(
                                Base64.getDecoder().decode(SECRET)),
                        Jwts.SIG.HS512)
                .compact();

        assertThrows(
                ExpiredJwtException.class,
                () -> jwtService.extractAllClaims(expiredToken));

        assertFalse(
                jwtService.isTokenValid(expiredToken, EMAIL));
    }
}
