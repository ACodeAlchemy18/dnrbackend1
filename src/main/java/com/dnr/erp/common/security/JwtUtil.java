package com.dnr.erp.common.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.UUID;

@Component
public class JwtUtil {

    private final String secret;
    private final long expirationMs;

    public JwtUtil(
        @Value("${app.jwt.secret}") String secret,
        @Value("${app.jwt.expiration-ms}") long expirationMs
    ) {
        this.secret = secret;
        this.expirationMs = expirationMs;
    }

    private Key getKey() {
        return Keys.hmacShaKeyFor(secret.getBytes());
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
