/**
 * Created by Mohammad Khalid Hasan
 * Since: 4/24/2024
 * Version: 1.0
 */

package com.example.security.authorization.security;

import com.example.security.common.security.JwtUtilsParseToken;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class AuthorizationFilter extends OncePerRequestFilter {
    private final JwtUtilsParseToken jwtUtils;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }
        UsernamePasswordAuthenticationToken token = getToken(header);

        SecurityContextHolder.getContext().setAuthentication(token);
        filterChain.doFilter(request, response);
    }

    private UsernamePasswordAuthenticationToken getToken(String header) {
        if (header != null) {
            String token = header.replace("Bearer ", "");
            String user = !jwtUtils.isTokenValid(token) ? null : jwtUtils.extractUser(token);
            if (user != null)
                return new UsernamePasswordAuthenticationToken(user, null, jwtUtils.extractAuthorities(token));
        }
        return null;
    }
}