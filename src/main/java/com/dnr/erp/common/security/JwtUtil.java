package com.dnr.erp.common.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;
import java.security.Key;
import java.util.Date;
import java.util.UUID;

@Component
public class JwtUtil {

    private final String secret;
    private final long expirationMs;
    private Key key;

    public JwtUtil(
        @Value("${app.jwt.secret}") String secret,
        @Value("${app.jwt.expiration-ms}") long expirationMs
    ) {
        this.secret = secret;
        this.expirationMs = expirationMs;
    }

    @PostConstruct
    public void init() {
        if (secret == null || secret.length() < 32) {
            throw new IllegalArgumentException(
                "JWT secret is missing or too short. Must be at least 32 characters."
            );
        }
        key = Keys.hmacShaKeyFor(secret.getBytes());
        System.out.println("JwtUtil initialized successfully with secret length: " + secret.length());
    }

    private Key getKey() {
        return key;
    }

    public String generateToken(UUID userId, Role role, String email, String fullName) {
        return Jwts.builder()
                .setSubject(userId.toString())
                .claim("role", role.name())
                .claim("email", email)
                .claim("name", fullName)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expirationMs))
                .signWith(getKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public Claims parseAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public Role extractUserRole(String token) {
        Claims claims = parseAllClaims(token);
        return Role.valueOf(claims.get("role", String.class));
    }

    public UUID validateAndExtractUserId(String token) {
        Claims claims = parseAllClaims(token);
        return UUID.fromString(claims.getSubject());
    }

    public boolean isTokenValid(String token) {
        try {
            parseAllClaims(token);
            return true;
        } catch (JwtException e) {
            return false;
        }
    }
}
