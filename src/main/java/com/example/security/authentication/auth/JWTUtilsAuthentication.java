package com.example.security.authentication.auth;

import com.example.security.common.security.JwtUtilsParseToken;
import com.example.security.common.model.User;
import com.example.security.authentication.repositories.TokenRepository;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.security.Key;

import java.util.Date;
import java.util.HashMap;
import java.util.List;

@Component
public class JWTUtilsAuthentication {
    private final TokenRepository tokenRepository;
    private final JwtUtilsParseToken jwtUtilsParseToken;

    @Value("${application.security.jwt.secret}")
    private String secretKey;

    @Value("${application.security.jwt.access-token-expiration}")
    private long accessTokenExpire;

    @Value("${application.security.jwt.refresh-token-expiration}")
    private long refreshTokenExpire;

    public JWTUtilsAuthentication(TokenRepository tokenRepository, JwtUtilsParseToken jwtUtilsParseToken) {
        this.tokenRepository = tokenRepository;
        this.jwtUtilsParseToken = jwtUtilsParseToken;
    }

    public String generateAccessToken(User user) {
        return generateToken(user, accessTokenExpire);
    }

    public String generateRefreshToken(User user) {
        return generateToken(user, refreshTokenExpire );
    }

    public String generateToken(User user, long expireTime) {
        List<String> roles = user.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList();

        HashMap<String, Object> claims = new HashMap<>();
        claims.put("roles", roles);
        return Jwts.builder()
                .addClaims(claims)
                .setSubject(user.getEmail())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expireTime))
                .signWith(SignatureAlgorithm.HS256, getSignInKey())
                .compact();
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public boolean isValidRefreshToken(String token, User user) {
        String username = jwtUtilsParseToken.extractUser(token);

        boolean validRefreshToken = tokenRepository
                .findByRefreshToken(token)
                .map(t -> !t.isLoggedOut())
                .orElse(false);

        return (username.equals(user.getUsername())) && !jwtUtilsParseToken.isTokenExpired(token) && validRefreshToken;
    }

}
