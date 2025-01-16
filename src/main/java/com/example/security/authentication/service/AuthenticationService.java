package com.example.security.authentication.service;

import com.example.security.authentication.auth.JWTUtilsAuthentication;
import com.example.security.common.security.JwtUtilsParseToken;
import com.example.security.common.model.AuthenticationResponse;
import com.example.security.common.model.Role;
import com.example.security.common.model.Token;
import com.example.security.common.model.User;
import com.example.security.controller.UserController;
import com.example.security.authentication.dto.AuthenticationDTO;
import com.example.security.common.exception.CustomException;
import com.example.security.authentication.repositories.RoleRepository;
import com.example.security.authentication.repositories.TokenRepository;
import com.example.security.common.repositories.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.ObjectUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private Logger log = LoggerFactory.getLogger(UserController.class);
    private final JWTUtilsAuthentication jwtUtilsAuthentication;
    private final JwtUtilsParseToken jwtUtilsParseToken;
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenRepository tokenRepository;
    private final RoleRepository featureRepository;

    public AuthenticationResponse register(User user) {
        if (!ObjectUtils.isEmpty(userRepository.findByEmail(user.getEmail()))) {
            throw new CustomException("User already exists", HttpStatus.BAD_REQUEST);
        }
        user.setPassword(passwordEncoder.encode(user.getPassword()));

        if (!ObjectUtils.isEmpty(user.getRoles())) {
            List<Role> roleList = new ArrayList<>();

            for (Role role : user.getRoles()) {
                Optional<Role> tmpRole = featureRepository.findByRoleName(role.getRoleName());

                if (tmpRole.isEmpty()) {
                    log.error("Role {} not exists", role.getRoleName());
                    throw new CustomException("Role not exists", HttpStatus.BAD_REQUEST);
                }
                roleList.add(tmpRole.get());
            }
            user.setRoles(roleList);
        }
        user = userRepository.save(user);

        String accessToken = jwtUtilsAuthentication.generateAccessToken(user);
        String refreshToken = jwtUtilsAuthentication.generateRefreshToken(user);

        saveUserToken(accessToken, refreshToken, user);

        return new AuthenticationResponse(accessToken, refreshToken, "User registration was successful");
    }

    public AuthenticationResponse login(AuthenticationDTO request) {
        log.info("try to track the error");
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                    request.getEmail(), request.getPassword()
            ));

            log.info("getting user");

            User user = userRepository.findByEmail(request.getEmail()).orElseThrow(() -> new CustomException("User not exists", HttpStatus.BAD_REQUEST));
            String accessToken = jwtUtilsAuthentication.generateAccessToken(user);
            String refreshToken = jwtUtilsAuthentication.generateRefreshToken(user);

            revokeAllTokenByUser(user);
            saveUserToken(accessToken, refreshToken, user);
            return new AuthenticationResponse(accessToken, refreshToken, "User login was successful");
        } catch (BadCredentialsException ex) {
            log.error("Bad credential exception {}", ex.getMessage());
            throw ex;
        }
    }

    private void saveUserToken(String accessToken, String refreshToken, User user) {
        Token token = new Token();
        token.setAccessToken(accessToken);
        token.setRefreshToken(refreshToken);
        token.setLoggedOut(false);
//        token.setUser(user);
        tokenRepository.save(token);
    }

    private void revokeAllTokenByUser(User user) {
        List<Token> validTokens = tokenRepository.findAllAccessTokensByUser(user.getId());
        if (validTokens.isEmpty()) {
            return;
        }

        validTokens.forEach(t -> {
            t.setLoggedOut(true);
        });

        tokenRepository.saveAll(validTokens);
    }

    public ResponseEntity refreshToken(HttpServletRequest request, HttpServletResponse response) {
        // extract the token from authorization header
        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return new ResponseEntity(HttpStatus.UNAUTHORIZED);
        }

        String token = authHeader.substring(7);

        // extract username from token
        String username = jwtUtilsParseToken.extractUser(token);

        // check if the user exist in database
        User user = userRepository.findByEmail(username)
                .orElseThrow(() -> new RuntimeException("No user found"));

        // check if the token is valid
        if (jwtUtilsAuthentication.isValidRefreshToken(token, user)) {
            // generate access token
            String accessToken = jwtUtilsAuthentication.generateAccessToken(user);
            String refreshToken = jwtUtilsAuthentication.generateRefreshToken(user);

            revokeAllTokenByUser(user);
            saveUserToken(accessToken, refreshToken, user);

            return new ResponseEntity(new AuthenticationResponse(accessToken, refreshToken, "New token generated"), HttpStatus.OK);
        }

        return new ResponseEntity(HttpStatus.UNAUTHORIZED);

    }
}
