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
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
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
    private final Logger log = LoggerFactory.getLogger(UserController.class);
    private final JWTUtilsAuthentication jwtUtilsAuthentication;
    private final JwtUtilsParseToken jwtParseToken;
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenRepository tokenRepository;
    private final RoleRepository featureRepository;

    /**
     * Registers a new user with the provided information.
     * generates an access token, and saves the user in the repository.
     *
     * @param  user  the user object to register
     * @return       an AuthenticationResponse object with the access token and registration status
     */
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
                    throw new CustomException("Role not exists", HttpStatus.BAD_REQUEST);}
                roleList.add(tmpRole.get());}
            user.setRoles(roleList);
        }

        user = userRepository.save(user);
        String accessToken = jwtUtilsAuthentication.generateAccessToken(user);
        if(accessToken != null){
            Token token = new Token();
            token.setAccessToken(accessToken);
            token.setUser(user);
            tokenRepository.save(token);
        }

        return new AuthenticationResponse(accessToken, null, "User registration was successful");
    }

    /**
     * Method to handle user login based on the provided request details.
     *
     * @param  request  the authentication request containing user credentials
     * @return          an AuthenticationResponse object with access token and login status
     */
    public AuthenticationResponse login(AuthenticationDTO request) {
        log.info("try to track the error");
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                    request.getEmail(), request.getPassword()
            ));

            log.info("getting user");

            User user = userRepository.findByEmail(request.getEmail()).orElseThrow(() -> new CustomException("User not exists", HttpStatus.BAD_REQUEST));

            Token token = tokenRepository.findByUser(user).orElseThrow(() -> new CustomException("User not exists with valid token", HttpStatus.BAD_REQUEST));

            /*
            Case 1: If access token is valid, Return access token.
            Case 2: If access token and refresh token both are null, Generate access token.
            Case 3: If access token is expired but valid refresh token is available, Return refresh token.
            Case 4: If refresh token exists but invalid, Generate refresh token.
             */

            if(token.getAccessToken() == null && token.getRefreshToken() == null) {
                token.setAccessToken(jwtUtilsAuthentication.generateAccessToken(user));
                tokenRepository.save(token);
                return new AuthenticationResponse(token.getAccessToken(), null, "User Logged in successfully with access token");
            }
                if(token.getAccessToken()==null || jwtParseToken.isTokenExpired(token.getAccessToken())) {
                    token.setAccessToken(null);
                    if(token.getRefreshToken() == null || jwtParseToken.isTokenExpired(token.getRefreshToken())) {
                            //when user have refresh token but expired
                            String refreshToken = jwtUtilsAuthentication.generateRefreshToken(user);
                            token.setRefreshToken(refreshToken);
                            tokenRepository.save(token);
                            return new AuthenticationResponse(null, refreshToken, "User Logged in successfully with new refresh token");
                        } else
                            return new AuthenticationResponse(null, token.getRefreshToken(), "User Logged in successfully with previous refresh token");
                    }
                else {
                    return new AuthenticationResponse(token.getAccessToken(), null, "User Logged in successfully with previous access token ");
                }
//            }
//            return new AuthenticationResponse(null, null, "User login was unsuccessful");
        } catch (BadCredentialsException ex) {
            log.error("Bad credential exception {}", ex.getMessage());
            throw ex;
        }
    }

    private void saveUserToken(String accessToken, String refreshToken, User user) {
        Token token = new Token();
        token.setAccessToken(accessToken);
//        token.setRefreshToken(refreshToken);
//        token.setLoggedOut(false);
        token.setUser(user);
        tokenRepository.save(token);
    }
}
