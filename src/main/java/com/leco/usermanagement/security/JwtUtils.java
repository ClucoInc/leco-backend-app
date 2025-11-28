package com.leco.usermanagement.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;

@Component
public class JwtUtils {

    @Value("${app.jwt.secret}")
    private String jwtSecret;

    @Value("${app.jwt.expiration-ms:3600000}")
    private long jwtExpirationMs;

    private Key getSigningKey() {
        // If your secret is Base64-encoded, decode it here instead:
        // byte[] keyBytes = java.util.Base64.getDecoder().decode(jwtSecret);
        byte[] keyBytes = jwtSecret.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateToken(String subject, List<String> roles, long expirationMs) {
        Claims claims = Jwts.claims().setSubject(subject);
        claims.put("roles", roles);
        long now = System.currentTimeMillis();
        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(new Date(now))
                .setExpiration(new Date(now + expirationMs))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    // convenience overload that uses configured expiration
    public String generateToken(String subject, List<String> roles) {
        return generateToken(subject, roles, jwtExpirationMs);
    }

    public boolean validateToken(String token) {
        if (token == null || token.isBlank()) return false;
        try {
            Jwts.parserBuilder().setSigningKey(getSigningKey()).build().parseClaimsJws(token);
            return true;
        } catch (JwtException | IllegalArgumentException ex) {
            return false;
        }
    }

    public String getSubject(String token) {
        try {
            return Jwts.parserBuilder().setSigningKey(getSigningKey()).build()
                    .parseClaimsJws(token).getBody().getSubject();
        } catch (JwtException | IllegalArgumentException ex) {
            return null;
        }
    }

    @SuppressWarnings("unchecked")
    public List<String> getRoles(String token) {
        List<String> roles = new ArrayList<>();
        if (token == null || token.isBlank()) return roles;
        try {
            Object raw = Jwts.parserBuilder().setSigningKey(getSigningKey()).build()
                    .parseClaimsJws(token).getBody().get("roles");
            if (raw instanceof Collection) {
                for (Object o : (Collection<?>) raw) {
                    if (o != null) roles.add(o.toString());
                }
            } else if (raw instanceof String) {
                for (String s : ((String) raw).split(",")) roles.add(s.trim());
            }
        } catch (JwtException | IllegalArgumentException ex) {
            // ignore
        }
        return roles;
    }
}