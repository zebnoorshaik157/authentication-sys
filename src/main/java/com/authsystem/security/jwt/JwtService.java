package com.authsystem.security.jwt;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

import java.util.Date;
import java.util.UUID;

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
        long expirationTime = 15 * 60 * 1000;

        return Jwts.builder()
                .subject(email)
                .claim("tokenType", "access")
                .issuedAt(new Date())
                .expiration(new Date(
                        System.currentTimeMillis() + expirationTime
                ))
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
                        System.currentTimeMillis() + expirationTime
                ))
                .signWith(getSigningKey(), Jwts.SIG.HS512)
                .compact();
    }

    // Extract all claims after verifying the token
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

    // Validate token and match email
    public boolean isTokenValid(String token, String email) {
        Claims claims = extractAllClaims(token);

        return email.equals(claims.getSubject())
                && claims.getExpiration().after(new Date());
    }
}