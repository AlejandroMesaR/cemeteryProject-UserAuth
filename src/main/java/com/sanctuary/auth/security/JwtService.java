package com.sanctuary.auth.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.function.Function;

@Service
public class JwtService {
    private static final String SECRET_KEY = "TuClaveSuperSecretaConAlMenos32Caracteres!!!"; 
    private static final Key key = Keys.hmacShaKeyFor(SECRET_KEY.getBytes());

    public String generateToken(UserDetails userDetails) {
        return Jwts.builder()
                .setSubject(userDetails.getUsername())
                .claim("role", userDetails.getAuthorities().stream()
                    .findFirst()
                    .map(GrantedAuthority::getAuthority)
                    .orElse("ROLE_USER"))
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60)) // 1 hora
                .signWith(key, SignatureAlgorithm.HS256) 
                .compact();
    }

    /** Extrae el username del token JWT */
    public String extractUsername(String token) {
      return extractClaim(token, Claims::getSubject);
  }

    public boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    private boolean isTokenExpired(String token) {
        // Permitir 5 minutos de tolerancia
        final long CLOCK_SKEW = 1000 * 60 * 5; 
        return extractClaim(token, Claims::getExpiration).before(new Date(System.currentTimeMillis() - CLOCK_SKEW));
    }

  /** Extrae un claim específico del token */
  private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
      final Claims claims = extractAllClaims(token);
      return claimsResolver.apply(claims);
  }

  /** Extrae todos los claims del token */
  private Claims extractAllClaims(String token) {
      return Jwts.parserBuilder()
              .setSigningKey(key)
              .build()
              .parseClaimsJws(token)
              .getBody();
  }
}
