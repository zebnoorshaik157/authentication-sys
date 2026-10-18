
package com.authsystem.security.jwt;

import java.util.Date;
import java.util.UUID;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {

    @Value("${jwt.secret}")
    private String secret;

    private SecretKey getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secret);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    // Generate Access Token (15 minutes)
    public String generateToken(String email) {
        long expirationTime = 15 * 60 * 1000L;

        return Jwts.builder()
                .subject(email)
                .claim("tokenType", "access")
                .issuedAt(new Date())
                .expiration(new Date(
                        System.currentTimeMillis() + expirationTime))
                .signWith(getSigningKey(), Jwts.SIG.HS512)
                .compact();
    }

    // Generate Refresh Token (7 days) with unique jti
    public String generateRefreshToken(String email) {
        long expirationTime = 7L * 24 * 60 * 60 * 1000;

        return Jwts.builder()
                .id(UUID.randomUUID().toString())
                .subject(email)
                .claim("tokenType", "refresh")
                .issuedAt(new Date())
                .expiration(new Date(
                        System.currentTimeMillis() + expirationTime))
                .signWith(getSigningKey(), Jwts.SIG.HS512)
                .compact();
    }

    // Generate Password Reset Token (10 minutes)
    public String generatePasswordResetToken(String email) {
        long expirationTime = 10 * 60 * 1000L;

        return Jwts.builder()
                .id(UUID.randomUUID().toString())
                .subject(email)
                .claim("tokenType", "password_reset")
                .issuedAt(new Date())
                .expiration(new Date(
                        System.currentTimeMillis() + expirationTime))
                .signWith(getSigningKey(), Jwts.SIG.HS512)
                .compact();
    }

    // Extract all claims after verifying the signature and expiration
    public Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    // Extract email from token
    public String extractEmail(String token) {
        return extractAllClaims(token).getSubject();
    }

    // Extract the unique JWT ID
    public String extractJti(String token) {
        return extractAllClaims(token).getId();
    }

    // Extract token expiration
    public Date extractExpiration(String token) {
        return extractAllClaims(token).getExpiration();
    }

    // Validate an access token and match its email
    public boolean isTokenValid(String token, String email) {
        try {
            Claims claims = extractAllClaims(token);

            return email != null
                    && email.equals(claims.getSubject())
                    && "access".equals(
                            claims.get("tokenType", String.class))
                    && claims.getExpiration() != null
                    && claims.getExpiration().after(new Date());

        } catch (Exception ex) {
            return false;
        }
    }
}
