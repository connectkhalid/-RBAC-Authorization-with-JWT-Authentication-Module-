package com.example.security.common.security;

import com.example.security.authentication.repositories.TokenRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
@NoArgsConstructor(force = true)
public class JwtUtilsParseToken {

    @Value("${application.security.jwt.secret}")
    private String secretKey;

    private final TokenRepository tokenRepository;

    public boolean isTokenValid(String token) {
        if (!isTokenExpired(token)) {
            return tokenRepository.existsByAccessToken(token);
        }
        return false;
    }

    public boolean isTokenExpired(String token) {
        try {
            Jwts.parser()
                    .verifyWith(getVerifyKey())
                    .build()
                    .parse(token);
            return false; // Token is not expired
        } catch (ExpiredJwtException ex) {
            return true; // Token is expired
        }
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> resolver) {
        Claims claims = extractAllClaims(token);
        return resolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        try {
            return Jwts
                    .parser()
                    .verifyWith(getVerifyKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (ExpiredJwtException ex) {
            // Handle the expired token exception
            // For example, you can return a specific error message or code
            throw new RuntimeException("Token has expired");
        }
    }

    public String extractUser(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public List<GrantedAuthority> extractAuthorities(String token) {
        Claims claims = getClaim(token);
        List<String> roles = claims.get("roles", List.class);

        return roles.stream()
                .map(role -> new SimpleGrantedAuthority(role.toUpperCase()))
                .collect(Collectors.toList());
    }

    public boolean revokeAllToken(String token){
        return isTokenValid(token) && tokenRepository.deleteAllByUserId(tokenRepository.findUserIdByAccessToken(token));
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    private Claims getClaim(String token) {
        Key key = getSignInKey(); // Make sure to provide the appropriate signing key
        return Jwts.parser()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private SecretKey getVerifyKey() {
        byte[] keyBytes = Decoders.BASE64URL.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}